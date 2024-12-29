DIR=$(dirname $BASH_SOURCE)
PROJECT_HOME=$(realpath $DIR/../../)
SYZ_HOME=$PROJECT_HOME/src/github.com/google/syzkaller/

DEBUG=""
if [ -n "$1" ]; then
    DEBUG="$1"
fi

$SYZ_HOME/bin/syz-manager -config actor.config "$DEBUG"
