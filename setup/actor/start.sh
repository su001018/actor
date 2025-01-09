DIR=$(dirname $BASH_SOURCE)
PROJECT_HOME=$(realpath $DIR/../../)
SYZ_HOME=$PROJECT_HOME/src/github.com/google/syzkaller/

# 文件前缀、大小和路径定义
FUZZER_PREFIX="ivshmemfilefuzzer-vm"
SCHEDULER_PREFIX="ivshmemfilescheduler-vm"
SIZE="512M"
PERMISSIONS=666
TARGET_PATH="/dev/shm"

# 函数定义：创建文件
create_file() {
    local FILE="$1"
    if [ ! -e "$FILE" ]; then
        echo "Creating $FILE..."
        dd if=/dev/zero of="$FILE" bs=1M count=512 status=progress
        chmod $PERMISSIONS "$FILE"
        echo "$FILE created with permissions $PERMISSIONS."
    else
        echo "$FILE already exists. Skipping creation."
    fi
}

# 使用循环创建文件
for i in {0..3}; do
    FUZZER_FILE="${TARGET_PATH}/${FUZZER_PREFIX}${i}"
    SCHEDULER_FILE="${TARGET_PATH}/${SCHEDULER_PREFIX}${i}"
    create_file "$FUZZER_FILE"
    create_file "$SCHEDULER_FILE"
done

DEBUG=""
if [ -n "$1" ]; then
    DEBUG="$1"
fi

$SYZ_HOME/bin/syz-manager -config actor.config "$DEBUG"
