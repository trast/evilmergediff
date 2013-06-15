#!/usr/bin/python

# Copyright (c) 2013, Thomas Rast <trast@inf.ethz.ch>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

'''Try a simple merge evilness detection.

At this point this is purely tree-based, so it cannot detect evilness
at a hunk level.'''

import sys
import subprocess
import optparse
from collections import defaultdict

usage = '%prog <merge> [ <parent1> <parent2> [--] [<mergebase>...] ]'
description = '''\
Show whether <merge> contains any candidates for file-level evilness.
The remaining args are optional, but the merge base in particular is
expensive to compute so you may want to provide it from a cache.

Works only on 2-parent merges.  (Octopus merges are not supposed to be
created from conflicting changes anyway.)'''

parser = optparse.OptionParser(usage=usage, description=description)
parser.add_option('--stdin', default=False, action='store_true', dest='stdin',
                  help='Read arguments from stdin (one set of args per line)')

def get_merge_bases(cmt1, cmt2):
    out = subprocess.check_output(['git', 'merge-base', '--all', cmt1, cmt2])
    return out.strip().split()

def get_parents(commit):
    out = subprocess.check_output(['git', 'rev-parse', commit+'^1', commit+'^2'])
    return out.strip().split()

def ls_tree(cmt):
    '''Call git-diff-tree and parse results

    The return value is a sequence with each element of the form
    (oldmode, newmode, oldhash, newhash, status, filename).

    FIXME: should convert to streaming input'''
    p = subprocess.Popen(['git', 'ls-tree', '-r', '-z', cmt],
                         stdout=subprocess.PIPE)
    data = p.stdout.read()
    for line in data.split('\0'):
        if not line: # last element is empty
            continue
        meta, filename = line.split('\t', 1)
        mode, type, sha = meta.split()
        yield (mode, sha, filename)
    ret = p.wait()
    assert ret == 0

# By convention the null sha1 is used to represent nonexistent files.
# We could use anything here, however.
nonexistent = '0'*40

def dict_ls_tree(cmt):
    '''Like ls_tree, but the result is a magic dict {filename:hash}.

    The magic part is that it is a defaultdict, returning the
    customary "absent" null sha1 if you ask for a file that was not in
    that tree.'''
    ret = defaultdict(lambda : nonexistent)
    for mode, sha, filename in ls_tree(cmt):
        ret[filename] = sha
    return ret, set(ret.keys())

def find_changed(fileset, tree1, tree2):
    ret = set()
    for f in fileset:
        if tree1[f] != tree2[f]:
            ret.add(f)
    return ret

def die(fmt, *fmtargs):
    sys.stderr.write(fmt % fmtargs)
    sys.exit(1)

def detect_evilness(M, A, B, bases):
    # History looks like this on a high level:
    #
    #    M
    #   / \
    #  A   B
    #   \ /
    #    Y1, Y2, ...
    #
    #
    # Obviously files are only interesting if A and B do not all have
    # the same content (otherwise the merge was trivial).
    #
    # There are two suspect cases, for any given file:
    #
    # (1) M agrees with A or B, but neither of them matches any
    #     merge-base.  In this case there should have been a
    #     nontrivial file-level merge.
    #
    # (2) M agrees with A (or B), but B (or A, resp.) does not match
    #     any merge-base.
    #
    # Actually (1) is a special case of (2).  However, I find it helps
    # to distinguish them and label them as
    # (1) modified in both, took <side>
    # (2) modified in <side>, took <other side>
    #
    # FIXME: need to think about what happens in rename detection
    # cases
    suspects = []
    treeM, filesM = dict_ls_tree(M)
    treeA, filesA = dict_ls_tree(A)
    treeB, filesB = dict_ls_tree(B)
    treeY, filesY = zip(*[dict_ls_tree(Y) for Y in bases])
    # We only care about files that are in at least one of M, A and B
    files_MAB = filesM.union(filesA).union(filesB)
    # and from those, only files that do not agree among all parents
    files_changed = (find_changed(files_MAB, treeA, treeM)
                     | find_changed(files_MAB, treeB, treeM))
    # case (1)
    for f in files_changed:
        if any(treeA[f] == t[f] for t in treeY):
            continue
        if any(treeB[f] == t[f] for t in treeY):
            continue
        if treeM[f] == treeA[f]:
            suspects.append((f, 'modified in both, took ^1'))
        elif treeM[f] == treeB[f]:
            suspects.append((f, 'modified in both, took ^2'))
    # don't look at the same files again
    files_changed.difference_update(f for f,reason in suspects)
    # case (2)
    def case2_helper(side1, side2, cause):
        for f in files_changed:
            if side1[f] != treeM[f]:
                continue
            if any(side2[f] == t[f] for t in treeY):
                continue
            suspects.append((f, cause))
    case2_helper(treeA, treeB, 'modified in ^2,   took ^1')
    case2_helper(treeB, treeA, 'modified in ^1,   took ^2')
    suspects.sort()
    return suspects


def process_args(args, unhandled_fatal=True):
    if len(args) > 3 and args[3] == '--':
        del args[3]
    if len(args) < 1:
        if not unhandled_fatal:
            return
        parser.print_usage()
        sys.exit(1)
    merge = args[0]
    parent1 = None
    parent2 = None
    bases = None
    if len(args) > 1:
        parent1 = args[1]
    if len(args) > 2:
        parent2 = args[2]
    if len(args) > 3:
        bases = args[3:]
    if not parent1 or not parent2:
        try:
            parent1, parent2 = get_parents(merge)
        except ValueError:
            if not unhandled_fatal:
                return
            die('%s does not appear to be a merge\n', merge)
    if not bases:
        bases = get_merge_bases(parent1, parent2)
    suspects = detect_evilness(merge, parent1, parent2, bases)
    if suspects:
        print "commit %s" % merge
        print "suspicious merge in files:"
        for filename, desc in suspects:
            print "\t%-25s\t%s" % (desc, filename)
        print

if __name__ == '__main__':
    options, args = parser.parse_args()
    if options.stdin:
        for line in sys.stdin:
            args = line.strip().split()
            process_args(args, unhandled_fatal=False)
    else:
        process_args(args)
