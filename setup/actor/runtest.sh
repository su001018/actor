DIR=$(dirname $BASH_SOURCE)
PROJECT_HOME=$(realpath $DIR/../../)
SYZ_HOME=$PROJECT_HOME/src/github.com/google/syzkaller/

TESTS=""
if [ -n "$1" ]; then
    TESTS="$1"
fi
$SYZ_HOME/bin/syz-runtest -config actor.config -debug -tests "$TESTS"