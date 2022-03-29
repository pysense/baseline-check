#!/bin/bash
# 基线检查脚本 by 1057 @ 2021-05-12

set -e
date=$(date +%Y%m%d_%H%M%S)
args="$@"

error() { echo "错误：$1"; exit 1; }
usage() {
    sed -n "2p" $0
    echo
    echo "支持检查项目："
    awk -F'"' '/^_item/{print$2}' $0 | sort -r
    echo
    echo "Usage:"
    echo "  $0 [-h]"
    echo "  $0 [-f|--cfg <config file>] # 指定配置文件"
    echo "  OUTPUT_SILENT=yes $0        # 隐藏基线符合项"
    echo
    exit
}

# 处理参数
ARGS=$(getopt \
    -o f:h \
    -l cfg:,help \
    -- "$@")
[[ $? -ne 0 ]] && error "参数错误。"

eval set -- "${ARGS}"

while true; do
    case "$1" in
        -f|--cfg) cfgfile="$2"; shift 2;;
        -h|--help) usage;;
        --) shift; break;;
        *) error "不支持的选项：$1";;
    esac
done

# 加载配置文件
if [[ -f $cfgfile ]]; then source $cfgfile; fi

# 脚本默认配置
OUTPUT_SILENT=${OUTPUT_SILENT:-no}                  # 是否隐藏基线符合项
OUTPUT_DETAIL=${OUTPUT_DETAIL:-yes}                 # 是否输出问题详情
OUTPUT_ADVISE=${OUTPUT_ADVISE:-yes}                 # 是否输出修复建议
BASELINE_APPLY=${BASELINE_APPLY:-no}                # 是否应用基线加固
BASELINE_RESTORE_FILE=baseline-restore-${date}.sh   # 应用加固策略后生成的回退脚本
SUID_SGID_FILES=(
/usr/bin/wall
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/chage
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/mount
/usr/bin/su
/usr/bin/sudo
/usr/bin/umount
/usr/bin/write
/usr/bin/pkexec
/usr/bin/crontab
/usr/bin/ssh-agent
/usr/bin/passwd
/usr/sbin/unix_chkpwd
/usr/sbin/pam_timestamp_check
/usr/sbin/netreport
/usr/sbin/usernetctl
/usr/sbin/postdrop
/usr/sbin/postqueue
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/libexec/utempter/utempter
/usr/libexec/dbus-1/dbus-daemon-launch-helper
/usr/libexec/openssh/ssh-keysign
/usr/bin/locate
/usr/bin/at
/var/lib/docker/
)

# 基线配置建议（参考 CIS）
PASS_MAX_DAYS=90
PASS_MIN_LEN=9

# Colors
ESC_SEQ="\x1b["
COL_RESET=$ESC_SEQ"39;49;00m"
COL_RED=$ESC_SEQ"31;01m"
COL_GREEN=$ESC_SEQ"32;01m"
COL_YELLOW=$ESC_SEQ"33;01m"
COL_BLUE=$ESC_SEQ"34;01m"
COL_MAGENTA=$ESC_SEQ"35;01m"
COL_CYAN=$ESC_SEQ"36;01m"

command_check() {
    for i in $*; do
        if ! command -v $i > /dev/null; then
            echo "错误：缺少依赖命令 $i"
            ERROR=1
        fi
    done
    if [[ -n $ERROR ]]; then exit $ERROR; fi
}
hr() {
    #if [[ $OUTPUT_SILENT == "yes" ]]; then return; fi
    if [[ $OUTPUT_SILENT == "yes" ]]; then
        if [[ $OUTPUT_DETAIL == "no" && $OUTPUT_ADVISE == "no" ]]; then
            return
        else
            printf '%*s\r' "${COLUMNS:-$(tput cols)}" '' | tr ' ' =
            return
        fi
    fi
    printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
}
checkitem() {
    hr
    printf "%s\r" "[*] $*"
}
checkitem_success() {
    if [[ $OUTPUT_SILENT == "yes" ]]; then
        printf '%*s\r' "${COLUMNS:-$(tput cols)}" ''
    else
        echo -e "$COL_GREEN[o]$COL_RESET"
    fi
}
checkitem_warn() {
    echo -e "$COL_RED[x]$COL_RESET"
}
checkitem_info() {
    echo -e "$COL_CYAN[~]$COL_RESET"
}
isos() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        if [[ ${1:-} == $ID ]]; then return 0; fi
    fi
    return 1
}

command_check sed awk grep systemctl

# Ubuntu 16.04 默认未安装 auditd
if ! command -v auditctl > /dev/null; then
    echo -e "$COL_RED[x] 未检测到 auditd 服务，以下项目将不会检测：$COL_RESET"
    echo -e "$COL_CYAN    **日志审计** 是否加载日志审计内核模块$COL_RESET"
    echo -e "$COL_CYAN    **日志审计** 是否开启日志审计服务$COL_RESET"
    logging_auditd_kernel=0
    logging_auditd_service=0
fi

# main
# ============================== **账号安全** ==============================
_item="**账号安全** 是否存在空口令账号"
_enable=1
_group="AccountSecurity"
if [[ $_enable == 1 ]]; then
    checkitem $_item
    _result=$(awk -F: '$2==""' /etc/shadow)
    if [[ -n $_result ]]; then
        checkitem_warn
        if [[ $OUTPUT_DETAIL == "yes" ]]; then
            echo "{{{ 问题详情"
            echo "/etc/shadow 文件异常"
            echo "$_result" | grep --color .
            echo "}}}"
        fi
        if [[ $OUTPUT_ADVISE == "yes" ]]; then
            echo "{{{ 修复建议"
            echo "为空口令账号设置密码（passwd <username>）或锁定该账号（passwd -l <username>）"
            echo "}}}"
        fi
    else checkitem_success; fi
fi

_item="**账号安全** 是否存在克隆账号"
_enable=1
_group="AccountSecurity"
if [[ $_enable == 1 ]]; then
    checkitem $_item
    _result=$(awk -F: '{uid[$3]++}END{for(i in uid)if(uid[i]>1)print i}' /etc/passwd)
    if [[ -n $_result ]]; then
        checkitem_warn
        if [[ $OUTPUT_DETAIL == "yes" ]]; then
            echo "{{{ 问题详情"
            echo "/etc/passwd 文件异常"
            for i in $_result; do
                echo "以下账号 UID 相同："
                awk -F: -v UID=$i '$3==UID' /etc/passwd | grep --color .
            done
            echo "}}}"
        fi
        if [[ $OUTPUT_ADVISE == "yes" ]]; then
            echo "{{{ 修复建议"
            echo "检查相同 UID 的账号"
            echo "}}}"
        fi
    else checkitem_success; fi
fi

_item="**账号安全** 是否存在 UID 为 0 的非 root 账号"
_enable=1
_group="AccountSecurity"
if [[ $_enable == 1 ]]; then
    checkitem $_item
    _result=$(awk -F: '$1!="root"&&$3==0' /etc/passwd)
    if [[ -n $_result ]]; then
        checkitem_warn
        if [[ $OUTPUT_DETAIL == "yes" ]]; then
            echo "{{{ 问题详情"
            echo "/etc/passwd 文件异常"
            echo "$_result" | grep --color .
            echo "}}}"
        fi
        if [[ $OUTPUT_ADVISE == "yes" ]]; then
            echo "{{{ 修复建议"
            echo "如果该账号不是自行创建的或者不是 root 重命名的，则应禁用该账号"
            echo "}}}"
        fi
    else checkitem_success; fi
fi

_item="**账号安全** 检查 root 账号是否锁定"
_enable=1
_group="AccountSecurity"
if [[ $_enable == 1 ]]; then
    checkitem $_item
    _result=$(awk -F: '$1=="root"&&$2~"[!*]+"' /etc/shadow)
    if [[ -n $_result ]]; then
        checkitem_info
        if [[ $OUTPUT_DETAIL == "yes" ]]; then
            echo "{{{ 问题详情"
            echo "root 账号未设置密码或账号锁定"
            echo "$_result" | grep --color .
            echo "}}}"
        fi
        if [[ $OUTPUT_ADVISE == "yes" ]]; then
            echo "{{{ 修复建议"
            echo "如果 root 账号未设置免密登录，或当前系统不存在其他管理账号，建议为 root 设置密码。"
            echo "}}}"
        fi
    else checkitem_success; fi
fi

_item="**账号安全** 可登录账号"
_enable=1
_group="AccountSecurity"
if [[ $_enable == 1 ]]; then
    checkitem $_item
    _result=$(sort -nk3 -t: /etc/passwd | grep -Eiv "^$|/(false|nologin|sync|shutdown|halt)$" || :)
    if [[ -n $_result ]]; then
        checkitem_info
        if [[ $OUTPUT_DETAIL == "yes" ]]; then
            echo "{{{ 问题详情"
            echo "$_result" | GREP_COLOR='1;36' grep --color .
            echo "}}}"
        fi
        if [[ $OUTPUT_ADVISE == "yes" ]]; then
            echo "{{{ 修复建议"
            echo "检查是否存在未知账号或无需登录权限的账号，如 MySQL 启动账号"
            echo "}}}"
        fi
    fi
fi

# ============================== **系统配置** ==============================
_item="**系统配置** 是否关闭 Core Dump"
_enable=1
_group=""
if [[ $_enable == 1 ]]; then
    checkitem $_item
    _file="/etc/security/limits.conf"
    _result=$(ulimit -c)
    if [[ $_result -ne 0 ]]; then
        checkitem_warn
        if [[ $OUTPUT_DETAIL == "yes" ]]; then
            echo "{{{ 问题详情"
            echo "$_result"
            echo "}}}"
        fi
        if [[ $OUTPUT_ADVISE == "yes" ]]; then
            echo "{{{ 修复建议"
            echo "修改配置文件 $_file，设置 * soft core 0 及 * hard core 0"
            echo "}}}"
        fi
    else checkitem_success; fi
fi

# ============================== **环境配置** ==============================
_item="**环境配置** 检查 PATH 变量是否包含当前目录"
_enable=1
_group=""
if [[ $_enable == 1 ]]; then
    checkitem $_item
    _result=$(echo $PATH | grep -Eo '(^|:)(\.|:|$)' || :)
    if [[ -n $_result ]]; then
        checkitem_warn
        if [[ $OUTPUT_DETAIL == "yes" ]]; then
            echo "{{{ 问题详情"
            echo $PATH | grep -E '(^|:)(\.|:|$)' --color
            echo "}}}"
        fi
        if [[ $OUTPUT_ADVISE == "yes" ]]; then
            echo "{{{ 修复建议"
            echo "检查 /etc/profile,~/.bash_profile,~/.bashrc 等配置文件中定义 PATH 变量的位置，移除非法的路径。"
            echo "}}}"
        fi
    else checkitem_success; fi
fi

_item="**环境配置** 检查 PATH 变量是否包含权限异常目录"
_enable=1
_group=""
if [[ $_enable == 1 ]]; then
    checkitem $_item
    _result=$(find $(echo ${PATH//:/ }) -type d -perm -777 2> /dev/null || :)
    if [[ -n $_result ]]; then
        checkitem_warn
        if [[ $OUTPUT_DETAIL == "yes" ]]; then
            echo "{{{ 问题详情"
            echo "$_result" | grep --color .
            echo "}}}"
        fi
        if [[ $OUTPUT_ADVISE == "yes" ]]; then
            echo "{{{ 修复建议"
            echo "设置目录为正常权限，从 PATH 中移除可疑目录"
            echo "}}}"
        fi
    else checkitem_success; fi
fi

_item="**环境配置** umask 值"
_enable=1
_group=""
if [[ $_enable == 1 ]]; then
    checkitem $_item
    _result=$(umask)
    if [[ $_result != 0027 ]]; then
        checkitem_warn
        if [[ $OUTPUT_DETAIL == "yes" ]]; then
            echo "{{{ 问题详情"
            umask -p | grep --color .
            echo "}}}"
        fi
        if [[ $OUTPUT_ADVISE == "yes" ]]; then
            echo "{{{ 修复建议"
            echo "1. 修改配置文件 /etc/profile，设置 umask 0027"
            echo "2. 执行命令 umask 0027 在当前终端生效"
            echo "}}}"
        fi
    else checkitem_success; fi
fi

_item="**环境配置** 系统空闲等待时间 TMOUT"
_enable=${env_tmout:-1}
_group=""
if [[ $_enable == 1 ]]; then
    checkitem $_item
    _result=$TMOUT
    if [[ -z $_result ]]; then
        checkitem_warn
        if [[ $OUTPUT_DETAIL == "yes" ]]; then
            echo "{{{ 问题详情"
            echo "未设置 TMOUT 变量" | grep --color .
            echo "}}}"
        fi
        if [[ $OUTPUT_ADVISE == "yes" ]]; then
            echo "{{{ 修复建议"
            echo "1. 修改配置文件 /etc/profile，设置 export TMOUT=600"
            echo "2. 执行命令 TMOUT=600 在当前终端生效"
            echo "}}}"
        fi
    else checkitem_success; fi
fi

# ============================== **密码策略** ==============================
_item="**密码策略** 密码最长使用天数"
_enable=${login_defs_pass_max_days:-1}
_group="AccountSecurity"
if [[ $_enable == 1 ]]; then
    checkitem $_item
    _file="/etc/login.defs"
    _string="PASS_MAX_DAYS $PASS_MAX_DAYS"
    _result=$(awk -v IGNORECASE=1 '/^\s*PASS_MAX_DAYS/{print$2}' $_file)
    if [[ $_result -gt $PASS_MAX_DAYS || -z $_result ]]; then
        checkitem_warn
        if [[ $OUTPUT_DETAIL == "yes" ]]; then
            echo "{{{ 问题详情"
            #awk -v IGNORECASE=1 '/^\s*PASS_MAX_DAYS/' $_file
            awk -v IGNORECASE=1 '/^\s*PASS_MAX_DAYS/{print FILENAME":"FNR":"$0}' $_file
            echo "}}}"
        fi
        if [[ $OUTPUT_ADVISE == "yes" ]]; then
            echo "{{{ 修复建议"
            echo "强制用户定期更改密码，PASS_MAX_DAYS 应小于或等于 $PASS_MAX_DAYS"
            echo "修改配置文件 $_file，设置 $_string"
            echo "}}}"
        fi
        if [[ $BASELINE_APPLY == "yes" ]]; then
            echo "{{{ 基线加固"
            echo "# $_item" >> $BASELINE_RESTORE_FILE
            _result=$(sed -nr "/^\s*PASS_MAX_DAYS/p" $_file)
            if [[ -n $_result ]]; then
                sed -i.blbak "/^\s*PASS_MAX_DAYS/c $_string" $_file
                echo "sed -i.blbak \"/^\s*PASS_MAX_DAYS/c $_result\" $_file" >> $BASELINE_RESTORE_FILE
            else
                sed -i.blbak "$ a $_string" $_file
                echo "sed -i.blbak \"/^\s*PASS_MAX_DAYS/d\" $_file" >> $BASELINE_RESTORE_FILE
            fi
            _result=$(sed -nr "/^\s*PASS_MAX_DAYS/p" $_file)
            echo $_result
            echo "}}}"
        fi
    else checkitem_success; fi
fi

# CentOS 配置在 /etc/login.defs
# Ubuntu 配置在 /etc/pam.d/common-password
_item="**密码策略** 密码最小长度"
_enable=${login_defs_pass_min_len:-1}
_group="AccountSecurity"
if [[ $_enable == 1 ]]; then
    checkitem $_item
    _file="/etc/login.defs"
    _string="PASS_MIN_LEN $PASS_MIN_LEN"
    _keyword="PASS_MIN_LEN"
    _result=$(awk -v IGNORECASE=1 '/^\s*PASS_MIN_LEN/{print$2}' $_file)
    if isos ubuntu; then
        _file="/etc/pam.d/common-password"
        _string="password [success=1 default=ignore] pam_unix.so obscure sha512 minlen=$PASS_MIN_LEN"
        _keyword="minlen"
        _result=$(sed -nr "s/^\s*[^#].*minlen=//p" $_file)
    fi
    if [[ $_result -lt $PASS_MIN_LEN || -z $_result ]]; then
        checkitem_warn
        if [[ $OUTPUT_DETAIL == "yes" ]]; then
            echo "{{{ 问题详情"
            #awk -v IGNORECASE=1 '/^\s*PASS_MIN_LEN/{print FILENAME":"FNR":"$0}' $_file
            awk -v IGNORECASE=1 '/^\s*[^#]*'$_keyword'/{print FILENAME":"FNR":"$0}' $_file
            echo "}}}"
        fi
        if [[ $OUTPUT_ADVISE == "yes" ]]; then
            echo "{{{ 修复建议"
            echo "强制用户设置的密码最小长度，$_keyword 应大于或等于 $PASS_MIN_LEN"
            echo "修改配置文件 $_file，设置 $_string"
            echo "}}}"
        fi
        if [[ $BASELINE_APPLY == "yes" ]]; then
            echo "{{{ 基线加固"
            echo "# $_item" >> $BASELINE_RESTORE_FILE
            _result=$(sed -nr "/^\s*[^#]*$_keyword/p" $_file)
            if [[ -n $_result ]]; then
                sed -i.blbak "/^\s*[^#]*$_keyword/c $_string" $_file
                echo "sed -i.blbak \"/^\s*[^#]*$_keyword/c $_result\" $_file" >> $BASELINE_RESTORE_FILE
            else
                if isos ubuntu; then
                    sed -i.blbak "/^\s*[^#]*password.*pam_unix.so/s/^/#_/" $_file
                    sed -i.blbak "$ a $_string" $_file
                    echo "sed -i.blbak \"/^\s*[^#]*$_keyword/d\" $_file" >> $BASELINE_RESTORE_FILE
                    echo "sed -i.blbak \"/^#_.*password.*pam_unix.so/s/^#_//\" $_file" >> $BASELINE_RESTORE_FILE
                else
                    sed -i.blbak "$ a $_string" $_file
                    echo "sed -i.blbak \"/^\s*[^#]*$_keyword/d\" $_file" >> $BASELINE_RESTORE_FILE
                fi
            fi
            _result=$(sed -nr "/^\s*[^#]*$_keyword/p" $_file)
            echo $_result
            echo "}}}"
        fi
    else checkitem_success; fi
fi

# ============================== **SSH 安全** ==============================
_item="**SSH 安全** 禁止 SSH 空口令登录"
_enable=${sshd_config_permitemptypasswords_no:-1}
_group="SSHSecurity"
if [[ $_enable == 1 ]]; then
    checkitem $_item
    _file="/etc/ssh/sshd_config"
    _string="PermitEmptyPasswords no"
    #_result=$(grep -Ei "^\s*PermitEmptyPasswords\s+yes" $_file || :)
    _result=$(awk -v IGNORECASE=1 '/^\s*PermitEmptyPasswords\s+yes/' $_file)
    if [[ -n $_result ]]; then
        checkitem_warn
        if [[ $OUTPUT_DETAIL == "yes" ]]; then
            echo "{{{ 问题详情"
            awk -v IGNORECASE=1 '/^\s*PermitEmptyPasswords\s+yes/{print FILENAME":"FNR":"$0}' $_file
            echo "}}}"
        fi
        if [[ $OUTPUT_ADVISE == "yes" ]]; then
            echo "{{{ 修复建议"
            echo "禁止 SSH 空口令登录"
            echo "1. 修改配置文件 $_file，设置 $_string"
            echo "2. 重启 sshd 服务"
            echo "}}}"
        fi
        if [[ $BASELINE_APPLY == "yes" ]]; then
            echo "{{{ 基线加固"
            echo "# $_item" >> $BASELINE_RESTORE_FILE
            _result=$(sed -nr "/^\s*PermitEmptyPasswords/p" $_file)
            if [[ -n $_result ]]; then
                sed -i.blbak "/^\s*PermitEmptyPasswords/c $_string" $_file
                echo "sed -i.blbak \"/^\s*PermitEmptyPasswords/c $_result\" $_file" >> $BASELINE_RESTORE_FILE
            else
                sed -i.blbak "$ a $_string" $_file
                echo "sed -i.blbak \"/^\s*PermitEmptyPasswords/d\" $_file" >> $BASELINE_RESTORE_FILE
            fi
            _result=$(sed -nr "/^\s*PermitEmptyPasswords/p" $_file)
            echo $_result
            post_command="systemctl restart sshd"
            $post_command
            echo "$post_command" >> $BASELINE_RESTORE_FILE
            echo "}}}"
        fi
    else checkitem_success; fi
fi

_item="**SSH 安全** 禁止 root 账号通过密码登录 SSH"
_enable=${sshd_config_permitrootlogin_prohibit_password:-1}
_group="SSHSecurity"
if [[ $_enable == 1 ]]; then
    checkitem $_item
    _file="/etc/ssh/sshd_config"
    _string="PermitRootLogin prohibit-password"
    #_result=$(grep -Ei "^\s*PermitRootLogin\s+[^y]+" $_file || :)
    _result=$(awk -v IGNORECASE=1 '/^\s*PermitRootLogin\s+[^y]+/' $_file)
    if [[ -z $_result ]]; then
        checkitem_warn
        if [[ $OUTPUT_DETAIL == "yes" ]]; then
            echo "{{{ 问题详情"
            echo "当前配置允许 root 账号通过密码登录 SSH"
            echo "}}}"
        fi
        if [[ $OUTPUT_ADVISE == "yes" ]]; then
            echo "{{{ 修复建议"
            echo "禁用 root 账号通过密码登录的能力，保留通过密钥登录的能力"
            echo "1. 修改配置文件 $_file，设置 $_string"
            echo "2. 重启 sshd 服务"
            echo -e "$COL_RED注意：如果 root 账号未配置密钥登录，将导致 root 账号无法登录 SSH。$COL_RESET"
            echo "}}}"
        fi
        # 注意：应用此基线加固有风险，如果未设置密钥登录将导致 SSH 无法登录
        if [[ $BASELINE_APPLY == "yes" ]]; then
            echo "{{{ 基线加固"
            echo "# $_item" >> $BASELINE_RESTORE_FILE
            _result=$(sed -nr "/^\s*PermitRootLogin/p" $_file)
            if [[ -n $_result ]]; then
                sed -i.blbak "/^\s*PermitRootLogin/c $_string" $_file
                echo "sed -i.blbak \"/^\s*PermitRootLogin/c $_result\" $_file" >> $BASELINE_RESTORE_FILE
            else
                sed -i.blbak "$ a $_string" $_file
                echo "sed -i.blbak \"/^\s*PermitRootLogin/d\" $_file" >> $BASELINE_RESTORE_FILE
            fi
            _result=$(sed -nr "/^\s*PermitRootLogin/p" $_file)
            echo $_result
            post_command="systemctl restart sshd"
            $post_command
            echo "$post_command" >> $BASELINE_RESTORE_FILE
            echo "}}}"
        fi
    else checkitem_success; fi
fi

_item="**SSH 安全** 禁用 UseDNS"
_enable=${sshd_config_usedns_no:-1}
_group="SSHSecurity"
if [[ $_enable == 1 ]]; then
    checkitem $_item
    _file="/etc/ssh/sshd_config"
    _string="UseDNS no"
    #_result=$(grep -Ei "^\s*UseDNS\s+[^y]+" $_file || :)
    _result=$(awk -v IGNORECASE=1 '/^\s*UseDNS\s+[^y]+/' $_file)
    if [[ -z $_result ]]; then
        checkitem_warn
        if [[ $OUTPUT_DETAIL == "yes" ]]; then
            echo "{{{ 问题详情"
            echo "当前配置下 sshd 将对远程主机名进行反向解析，以检查此主机名是否与其IP地址真实对应。（在无法解析时导致增加登录耗时）"
            echo "}}}"
        fi
        if [[ $OUTPUT_ADVISE == "yes" ]]; then
            echo "{{{ 修复建议"
            echo "1. 修改配置文件 $_file，设置 $_string"
            echo "2. 重启 sshd 服务"
            echo "}}}"
        fi
        if [[ $BASELINE_APPLY == "yes" ]]; then
            echo "{{{ 基线加固"
            echo "# $_item" >> $BASELINE_RESTORE_FILE
            _result=$(sed -nr "/^\s*UseDNS/p" $_file)
            if [[ -n $_result ]]; then
                sed -i.blbak "/^\s*UseDNS/c $_string" $_file
                echo "sed -i.blbak \"/^\s*UseDNS/c $_result\" $_file" >> $BASELINE_RESTORE_FILE
            else
                sed -i.blbak "$ a $_string" $_file
                echo "sed -i.blbak \"/^\s*UseDNS/d\" $_file" >> $BASELINE_RESTORE_FILE
            fi
            _result=$(sed -nr "/^\s*UseDNS/p" $_file)
            echo $_result
            post_command="systemctl restart sshd"
            $post_command
            echo "$post_command" >> $BASELINE_RESTORE_FILE
            echo "}}}"
        fi
    else checkitem_success; fi
fi

# ============================== **文件权限** ==============================
_item="**文件权限** 任何人都有写权限的文件"
_enable=1
_group=""
if [[ $_enable == 1 ]]; then
    checkitem $_item
    _result=$(find $(awk -v IGNORECASE=1 '$0~/^\s*[^#]/&&$2!~/swap|\/proc|\/dev/{print$2}' /etc/fstab) -xdev -type f \( -perm -0002 -a ! -perm -1000 \))
    if [[ -n $_result ]]; then
        checkitem_warn
        if [[ $OUTPUT_DETAIL == "yes" ]]; then
            echo "{{{ 问题详情"
            echo "$_result"
            echo "}}}"
        fi
        if [[ $OUTPUT_ADVISE == "yes" ]]; then
            echo "{{{ 修复建议"
            echo "检查文件权限是否正常"
            echo "}}}"
        fi
    else checkitem_success; fi
fi

_item="**文件权限** 任何人都有写权限的目录"
_enable=1
_group=""
if [[ $_enable == 1 ]]; then
    checkitem $_item
    _result=$(find $(awk -v IGNORECASE=1 '$0~/^\s*[^#]/&&$2!~/swap|\/proc|\/dev/{print$2}' /etc/fstab) -xdev -type d \( -perm -0002 -a ! -perm -1000 \))
    if [[ -n $_result ]]; then
        checkitem_warn
        if [[ $OUTPUT_DETAIL == "yes" ]]; then
            echo "{{{ 问题详情"
            echo "$_result"
            echo "}}}"
        fi
        if [[ $OUTPUT_ADVISE == "yes" ]]; then
            echo "{{{ 修复建议"
            echo "检查目录权限是否正常"
            echo "}}}"
        fi
    else checkitem_success; fi
fi

_item="**文件权限** 检查没有属主或属组的文件"
_enable=1
_group=""
if [[ $_enable == 1 ]]; then
    checkitem $_item
    _result=$(find $(awk -v IGNORECASE=1 '$0~/^\s*[^#]/&&$2!~/swap|\/proc|\/dev/{print$2}' /etc/fstab) -xdev -nouser -o -nogroup)
    if [[ -n $_result ]]; then
        checkitem_warn
        if [[ $OUTPUT_DETAIL == "yes" ]]; then
            echo "{{{ 问题详情"
            echo "$_result"
            echo "}}}"
        fi
        if [[ $OUTPUT_ADVISE == "yes" ]]; then
            echo "{{{ 修复建议"
            echo "可能情况："
            echo "1. 变更过 /etc/passwd 账号 UID/GID"
            echo "2. 文件所属账号/组已经删除"
            echo "3. 从其他主机下载的压缩包中解压的文件"
            echo "}}}"
        fi
    else checkitem_success; fi
fi

_item="**文件权限** 检查可疑隐藏文件"
_enable=1
_group=""
if [[ $_enable == 1 ]]; then
    checkitem $_item
    _result=$(find $(awk -v IGNORECASE=1 '$0~/^\s*[^#]/&&$2!~/swap|\/proc|\/dev/{print$2}' /etc/fstab) -xdev -name ".. *" -o -name "...*")
    if [[ -n $_result ]]; then
        checkitem_warn
        if [[ $OUTPUT_DETAIL == "yes" ]]; then
            echo "{{{ 问题详情"
            echo "$_result"
            echo "}}}"
        fi
        if [[ $OUTPUT_ADVISE == "yes" ]]; then
            echo "{{{ 修复建议"
            echo "检查输出文件/目录是否异常"
            echo "}}}"
        fi
    else checkitem_success; fi
fi

_item="**文件权限** 检查 SUID/SGID 文件"
_enable=1
_group=""
if [[ $_enable == 1 ]]; then
    checkitem $_item
    _result=$(find $(awk -v IGNORECASE=1 '$0~/^\s*[^#]/&&$2!~/swap|\/proc|\/dev/{print$2}' /etc/fstab) -xdev ! -path "/var/lib/docker/*" \( -perm -4000 -o -perm -2000 \))
    if [[ -n $_result ]]; then
        for i in $_result; do
            if command -v rpm > /dev/null; then
                if rpm -Vf $i | grep -q $i; then
                    _SUID_SGID_FILES+=($i)
                fi
            else
                if [[ ! ${SUID_SGID_FILES[@]} =~ "$i" ]]; then
                    _SUID_SGID_FILES+=($i)
                fi
            fi
        done
        if [[ ${#_SUID_SGID_FILES[@]} > 0 ]]; then
            checkitem_warn
            if [[ $OUTPUT_DETAIL == "yes" ]]; then
                echo "{{{ 问题详情"
                for i in ${_SUID_SGID_FILES[@]}; do
                    ls -lhd --color=auto --time-style=long-iso $i
                done
                echo "}}}"
            fi
            if [[ $OUTPUT_ADVISE == "yes" ]]; then
                echo "{{{ 修复建议"
                echo "检查输出文件/目录权限是否异常"
                echo "}}}"
            fi
        else
            checkitem_success
        fi
    else checkitem_success; fi
fi

# ============================== **日志审计** ==============================
_item="**日志审计** 是否开启安全日志"
_enable=1
_group=""
if [[ $_enable == 1 ]]; then
    checkitem $_item
    _file="/etc/rsyslog.conf /etc/rsyslog.d/*.conf"
    _string="authpriv.* /var/log/secure"
    if isos ubuntu; then
        _string="auth,authpriv.* /var/log/auth.log"
    fi
    _result=$(awk -v IGNORECASE=1 '/^\s*[^#]*authpriv\.[^n]/' $_file)
    if [[ -z $_result ]]; then
        checkitem_warn
        if [[ $OUTPUT_DETAIL == "yes" ]]; then
            echo "{{{ 问题详情"
            echo "未配置 authpriv.*"
            echo "}}}"
        fi
        if [[ $OUTPUT_ADVISE == "yes" ]]; then
            echo "{{{ 修复建议"
            echo "修改配置文件 $_file，设置 $_string"
            echo "}}}"
        fi
    else checkitem_success; fi
fi

_item="**日志审计** 是否加载日志审计内核模块"
_enable=${logging_auditd_kernel:-1}
_group=""
if [[ $_enable == 1 ]]; then
    checkitem $_item
    _result=$(auditctl -s 2> /dev/null | awk '/^enabled/{print$2}')
    if [[ $_result -ne 1 ]]; then
        checkitem_warn
        if [[ $OUTPUT_DETAIL == "yes" ]]; then
            echo "{{{ 问题详情"
            echo "enabled $_result"
            echo "}}}"
        fi
        if [[ $OUTPUT_ADVISE == "yes" ]]; then
            echo "{{{ 修复建议"
            echo "执行命令 auditctl -e 1 启用日志审计内核模块"
            echo "}}}"
        fi
    else checkitem_success; fi
fi

_item="**日志审计** 是否开启日志审计服务"
_enable=${logging_auditd_service:-1}
_group=""
if [[ $_enable == 1 ]]; then
    checkitem $_item
    _result=$(systemctl status auditd | grep "active (running)" || :)
    if [[ -z $_result ]]; then
        checkitem_warn
        if [[ $OUTPUT_DETAIL == "yes" ]]; then
            echo "{{{ 问题详情"
            systemctl status auditd | grep -i "Active:" || :
            echo "}}}"
        fi
        if [[ $OUTPUT_ADVISE == "yes" ]]; then
            echo "{{{ 修复建议"
            echo "执行以下命令启用日志审计服务"
            echo "systemctl enable auditd"
            echo "systemctl start auditd"
            echo "}}}"
        fi
    else checkitem_success; fi
fi

_item="**日志审计** 是否开启 cron 守护进程日志"
_enable=1
_group=""
if [[ $_enable == 1 ]]; then
    checkitem $_item
    _file="/etc/rsyslog.conf /etc/rsyslog.d/*.conf"
    _string="cron.* /var/log/cron"
    _result=$(awk -v IGNORECASE=1 '/^\s*[^#]*cron\.[^n]/' $_file)
    if [[ -z $_result ]]; then
        checkitem_warn
        if [[ $OUTPUT_DETAIL == "yes" ]]; then
            echo "{{{ 问题详情"
            echo "未配置 cron.*"
            echo "}}}"
        fi
        if [[ $OUTPUT_ADVISE == "yes" ]]; then
            echo "{{{ 修复建议"
            echo "修改配置文件 $_file，设置 $_string"
            echo "}}}"
        fi
    else checkitem_success; fi
fi

# ============================== **网络配置** ==============================
_item="**网络配置** sysctl 允许 ping 请求"
_enable=1
_group=""
if [[ $_enable == 1 ]]; then
    checkitem $_item
    # sysctl net.ipv4.icmp_echo_ignore_all | awk '{print$3}'
    _file="/etc/sysctl.conf"
    _string="net.ipv4.icmp_echo_ignore_all = 0"
    _result=$(cat /proc/sys/net/ipv4/icmp_echo_ignore_all)
    if [[ $_result -ne 0 ]]; then
        checkitem_warn
        if [[ $OUTPUT_DETAIL == "yes" ]]; then
            echo "{{{ 问题详情"
            echo "当前配置禁止 ping 请求，可能导致监控无法正常工作"
            echo "}}}"
        fi
        if [[ $OUTPUT_ADVISE == "yes" ]]; then
            echo "{{{ 修复建议"
            echo "1. 修改配置文件 $_file，设置 $_string"
            echo "2. 执行命令：sysctl net.ipv4.icmp_echo_ignore_all=0"
            #echo "执行命令：echo "0" > /proc/sys/net/ipv4/icmp_echo_ignore_all"
            echo "}}}"
        fi
        if [[ $BASELINE_APPLY == "yes" ]]; then
            echo "{{{ 基线加固"
            echo "# $_item" >> $BASELINE_RESTORE_FILE
            echo "sysctl $(sysctl net.ipv4.icmp_echo_ignore_all | sed 's/ //g')" >> $BASELINE_RESTORE_FILE
            _result=$(sed -nr "/^\s*net.ipv4.icmp_echo_ignore_all/p" $_file)
            if [[ -n $_result ]]; then
                sed -i.blbak "/^\s*net.ipv4.icmp_echo_ignore_all/c $_string" $_file
                echo "sed -i.blbak \"/^\s*net.ipv4.icmp_echo_ignore_all/c $_result\" $_file" >> $BASELINE_RESTORE_FILE
            else
                sed -i.blbak "$ a $_string" $_file
                echo "sed -i.blbak \"/^\s*net.ipv4.icmp_echo_ignore_all/d\" $_file " >> $BASELINE_RESTORE_FILE
            fi
            sysctl net.ipv4.icmp_echo_ignore_all=0
            echo "}}}"
        fi
    else checkitem_success; fi
fi

# ============================== **关键文件** ==============================
_item="**关键文件** /etc/passwd"
_enable=1
_group=""
if [[ $_enable == 1 ]]; then
    checkitem $_item
    _file="/etc/passwd"
    _string=""
    _result=$(lsattr $_file | cut -d" " -f1)
    if [[ $_result =~ ----i--------[e-]-- ]]; then
        checkitem_info
        if [[ $OUTPUT_DETAIL == "yes" ]]; then
            echo "{{{ 问题详情"
            echo "$_file 存在额外属性：$_result"
            echo "}}}"
        fi
        if [[ $OUTPUT_ADVISE == "yes" ]]; then
            echo "{{{ 修复建议"
            echo "可通过 chattr 命令修改额外属性，如该配置正常可忽略。"
            echo "}}}"
        fi
    else checkitem_success; fi
fi

# Summary
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
echo "检查日期：$(date +"%Y-%m-%d %H:%M:%S")"
echo "检查命令：$0 $args"
echo
echo "- 配置文件：${cfgfile:-无}"
echo "- 配置项"
echo "  - OUTPUT_SILENT=${OUTPUT_SILENT} # 隐藏基线符合项"
echo "  - OUTPUT_DETAIL=${OUTPUT_DETAIL} # 输出问题详情"
echo "  - OUTPUT_ADVISE=${OUTPUT_ADVISE} # 输出修复建议"
echo "  - BASELINE_APPLY=${BASELINE_APPLY} # 应用基线加固"
if [[ ${BASELINE_APPLY:-no} == yes ]]; then
    echo "    - BASELINE_RESTORE_FILE=${BASELINE_RESTORE_FILE} # 基线加固回退脚本"
fi
echo
