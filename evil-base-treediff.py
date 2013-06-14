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

usage = '%prog <merge> [ <parent1> <parent2> [--] [<mergebase>] ]'
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

def diff_tree(cmt1, cmt2):
    '''Call git-diff-tree and parse results

    The return value is a sequence with each element of the form
    (oldmode, newmode, oldhash, newhash, status, filename).

    FIXME: should convert to streaming input'''
    p = subprocess.Popen(['git', 'diff-tree', '-r', '-z', cmt1, cmt2],
                         stdout=subprocess.PIPE)
    data = p.stdout.read()
    chunks = data.split('\0')
    for meta, filename in zip(chunks[::2], chunks[1::2]):
        mode1, mode2, hash1, hash2, status = meta.split()
        yield (mode1, mode2, hash1, hash2, status, filename)
    ret = p.wait()
    assert ret == 0

def simple_diff_tree(cmt1, cmt2):
    '''Like diff_tree, but the result is a dict {filename:(oldhash,newhash)}.'''
    ret = {}
    # print "DEBUG: tree diff %s - %s" % (cmt1[:7], cmt2[:7])
    for mode1, mode2, hash1, hash2, status, filename in diff_tree(cmt1, cmt2):
        ret[filename] = (hash1, hash2)
    # for k,(h1,h2) in sorted(ret.items()):
    #     print "%s %s   %s" % (h1[:7], h2[:7], k)
    return ret

def die(fmt, *fmtargs):
    sys.stderr.write(fmt % fmtargs)
    sys.exit(1)

def detect_evilness(M, A, B, Y):
    # print 'M', M
    # print 'A', A
    # print 'B', B
    # print 'Y', Y
    # History looks like this on a high level:
    #
    #    M
    #   / \
    #  A   B
    #   \ /
    #    Y
    #
    # We look at two suspect cases:
    #
    # (1) If a file has been changed on Y..A, and also changed on
    #     Y..B, there should have been a file-level merge to build M.
    #     For such candidate files, the merge should have been
    #     nontrivial at the file level, i.e., the file should be
    #     modified on A..M and B..M, too.
    #
    # (2) If a file has been changed on exactly one of Y..A or Y..B,
    #     then the merge should not have taken the unchanged version.
    #     (Usually M took the changed one, but if it is completely
    #     new, --cc will show that so we are happy, too.)
    #
    # FIXME: need to think about what happens in rename detection
    # cases
    suspects = []
    dYA = simple_diff_tree(Y, A)
    dYB = simple_diff_tree(Y, B)
    dAM = simple_diff_tree(A, M)
    dBM = simple_diff_tree(B, M)
    # split the files into groups
    set_dYA = set(dYA.keys())
    set_dYB = set(dYB.keys())
    changed_AB = set_dYA.intersection(set_dYB)
    changed_A = set_dYA.difference(set_dYB)
    changed_B = set_dYB.difference(set_dYA)
    # case (1)
    for f in changed_AB:
        if f not in dAM:
            suspects.append((f, 'modified in both, took ^1'))
        elif f not in dBM:
            suspects.append((f, 'modified in both, took ^2'))
    # case (2)
    def case2_helper(changed_x, dYx, dyM, cause):
        for f in changed_x:
            fY, fx = dYx[f]
            if f not in dyM:
                suspects.append((f, cause))
                continue
            fy, fM = dyM[f]
            if fM == fy: # a mode change could fool us
                suspects.append((f, cause))
    case2_helper(changed_A, dYA, dBM, 'modified in ^1,   took ^2')
    case2_helper(changed_B, dYB, dAM, 'modified in ^2,   took ^1')
    suspects.sort()
    return suspects


def process_args(args, unhandled_fatal=True):
    if len(args) > 3 and args[3] == '--':
        del args[3]
    if len(args) < 1 or len(args) > 4:
        if not unhandled_fatal:
            return
        parser.print_usage()
        sys.exit(1)
    merge = args[0]
    parent1 = None
    parent2 = None
    base = None
    if len(args) > 1:
        parent1 = args[1]
    if len(args) > 2:
        parent2 = args[2]
    if len(args) > 3:
        base = args[3]
    if not parent1 or not parent2:
        try:
            parent1, parent2 = get_parents(merge)
        except ValueError:
            if not unhandled_fatal:
                return
            die('%s does not appear to be a merge\n', merge)
    if not base:
        bases = get_merge_bases(parent1, parent2)
        if len(bases) != 1:
            if not unhandled_fatal:
                return
            die("%s and %s have multiple merge bases; I don't handle this yet\n",
                parent1, parent2)
        base = bases[0]
    suspects = detect_evilness(merge, parent1, parent2, base)
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
