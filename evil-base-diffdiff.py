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

'''Try a diff-based merge evilness detection.'''

import sys
import subprocess
import optparse
from collections import defaultdict
from itertools import takewhile
import difflib

usage = '%prog <merge> [ <parent1> <parent2> [--] [<mergebase>...] ]'
description = '''\
Show whether <merge> contains any candidates for hunk level evilness.
The remaining args are optional, but the merge base in particular is
expensive to compute so you may want to provide it from a cache.

Works only on 2-parent merges.  (Octopus merges are not supposed to be
created from conflicting changes anyway.)'''

parser = optparse.OptionParser(usage=usage, description=description)
parser.add_option('--stdin', default=False, action='store_true', dest='stdin',
                  help='Read arguments from stdin (one set of args per line)')

def get_merge_bases(cmt1, cmt2):
    try:
        out = subprocess.check_output(['git', 'merge-base', '--all', cmt1, cmt2])
        return out.strip().split()
    except subprocess.CalledProcessError, e:
        # merge-base fails with status 1 if there are no bases
        if e.returncode == 1:
            return []
        raise

def get_parents(commit):
    out = subprocess.check_output(['git', 'rev-parse', commit+'^1', commit+'^2'])
    return out.strip().split()

def die(fmt, *fmtargs):
    sys.stderr.write(fmt % fmtargs)
    sys.exit(1)


def split_diff(data):
    diff = {}
    hunk = []
    for line in iter(data.splitlines(True)):
        if line.startswith('diff '):
            if len(hunk):
                diff[filename].append(hunk)
                hunk = []
            continue
        elif line.startswith('--- '):
            continue
        elif line.startswith('+++ '):
            filename = line[4:].rstrip('\n')
            if filename.startswith('b/'):
                filename = filename[2:]
            diff[filename] = []
            hunk = []
            continue
        elif line.startswith('index '):
            continue
        elif line.startswith('@@ '):
            if len(hunk):
                diff[filename].append(hunk)
                hunk = []
            continue
        elif len(line) and line[0] in '+- \\':
            hunk.append(line)
    if len(hunk):
        diff[filename].append(hunk)
        hunk = []
    return diff

def get_diff(cmt1, cmt2):
    # FIXME allow custom args to tweak the diff
    try:
        out = subprocess.check_output(['git', 'diff', '-M', cmt1, cmt2])
        return split_diff(out)
    except subprocess.CalledProcessError, e:
        # git-diff fails with status 1 if there are no differences
        if e.returncode == 1:
            return {}
        raise

def assemble_hunks(hunkseq):
    sep = []
    out = []
    for hunk in hunkseq:
        out.extend(sep)
        out.extend(hunk)
        sep = ['@@\n']
    return out


def any_suspicious_lines(diff):
    in_hunk = False
    for line in diff:
        if line.startswith('@@ '):
            in_hunk = True
            continue
        if not in_hunk:
            continue
        if line[:2] in ('--', '+-', '-+', '++'):
            return True
    return False


def remove_common_hunks(d1, d2):
    d1new = dict(d1)
    d2new = dict(d2)
    f1 = set(d1.keys())
    f2 = set(d2.keys())
    for f in f1 & f2:
        hunks1 = set(''.join(h) for h in d1[f])
        hunks2 = set(''.join(h) for h in d2[f])
        d1new[f] = [h for h in d1[f] if ''.join(h) not in hunks2]
        d2new[f] = [h for h in d2[f] if ''.join(h) not in hunks1]
    return d1new, d2new


def find_suspicious_hunks(dxM, dYx):
    '''Generate hunkwise interdiffs, trying to find a good match.'''
    # FIXME: this quick&dirty version assumes a single merge-base
    diff = {}
    files = set(dxM.keys()).union(dYx[0].keys())
    for f in files:
        pre = dYx[0].get(f, [])
        post = dxM.get(f, [])
        # might try something smarter, but this is a quick way
        pre_t = assemble_hunks(pre)
        post_t = assemble_hunks(post)
        delta = list(difflib.unified_diff(pre_t, post_t, f, f))
        if any_suspicious_lines(delta):
            diff[f] = delta
    return diff


def print_idiff(idiff, header):
    if not idiff:
        return
    print header
    for f, diff in idiff.iteritems():
        print "    %s" % f
        for line in diff:
            print "        %s" % line,


def abbrev(sha):
    return sha[:7] # FIXME (or not)


def detect_evilness(M, A, B, bases):
    dAM = get_diff(A, M)
    dBM = get_diff(B, M)
    dYA = [get_diff(Y, A) for Y in bases]
    dYB = [get_diff(Y, B) for Y in bases]
    for i in range(len(bases)):
        dYA[i], dYB[i] = remove_common_hunks(dYA[i], dYB[i])
    idiff_A = find_suspicious_hunks(dAM, dYB)
    idiff_B = find_suspicious_hunks(dBM, dYA)
    if idiff_A or idiff_B:
        print 'commit %s' % M
        print 'parents', abbrev(A), abbrev(B)
        print 'merge bases', ' '.join(abbrev(Y) for Y in bases)
    print_idiff(idiff_A, "suspicious hunks from %s..%s" % (abbrev(A), abbrev(M)))
    print_idiff(idiff_B, "suspicious hunks from %s..%s" % (abbrev(B), abbrev(M)))


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
