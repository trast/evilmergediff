#!/bin/sh

# !!! WARNING !!!
# THIS IS PURELY EXPERIMENTAL. DO NOT RUN IT. IT WILL EAT YOUR REPO.

USAGE="$0 <merge_commit>"
SUBDIRECTORY_OK=t
. "$(git --exec-path)/git-sh-setup"

cd "$GIT_DIR"
export GIT_DIR="$(pwd -P)"

tmpdir="$(mktemp -d)"
cp HEAD "$tmpdir/HEAD_backup"
cleanup () {
	test -n "$tmpdir" || return
	cp -f "$tmpdir/HEAD_backup" HEAD
	rm -rf "$tmpdir"
}
trap cleanup EXIT

export GIT_NOTES_REF=refs/notes/remerge-cache


# note_add () {
# 	note=$1
# 	commit=$2
# 	cat <<EOF | git fast-import
# commit $GIT_NOTES_REF
# committer $(git var GIT_COMMITTER_IDENT)
# data 31
# Note added via git-fast-import
# 
# from refs/notes/remerge-cache^0
# N $note $commit
# EOF
# }

remerge () {
	commit=$1
	parents="$(git rev-list --no-walk --pretty="%P" "$commit" | grep -v ^commit)"
	case "$parents" in
		*" "*" "*)
			die "$commit has more than 2 parents; fix me first"
			;;
		*" "*)
			;;
		*)
			die "$commit is not a merge commit"
			;;
	esac
	first=${parents%% *}
	second=${parents##* }

	export GIT_WORK_TREE="$tmpdir/worktree"
	mkdir "$GIT_WORK_TREE"
	export GIT_INDEX_FILE="$tmpdir/index"
	(
		cd "$GIT_WORK_TREE"
		git update-ref HEAD $first
		git read-tree $first
		git checkout -f -- .
		git merge --no-commit $second
		#git reset
		git add -A
	)
	tree=$(git write-tree)
}

test $# -eq 1 || usage

remerge "$1"
git diff "$tree" "$1"
