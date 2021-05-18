#!/bin/bash
# 基线检查脚本 by 1057 @ 2021-05-12
# TODO
# 增加参数：是否输出建议
# 增加参数：是否输出详情
# 增加参数：是否只输出问题项
# 多系统适配
# 支持加固，支持加固后回退

set -e
date=$(date +%Y%m%d_%H%M%S)

# 脚本配置项
OUTPUT_SILENT=${OUTPUT_SILENT:-no}                  # 是否输出基线符合项
OUTPUT_DETAIL=${OUTPUT_DETAIL:-yes}                 # 是否输出详情
OUTPUT_ADVISE=${OUTPUT_ADVISE:-yes}                 # 是否输出建议
BASELINE_APPLY=${BASELINE_APPLY:-no}                # 是否应用加固策略
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
)

# 基线配置建议
PASS_MAX_DAYS=42
PASS_MIN_LEN=8

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
usage() {
    sed -n "2p" $0
    echo "Usage: $0 [-h]"
    echo
    echo "支持检查项目："
    awk '/^checkitem\s/' $0 | sort -k2 | awk -F'**' '{print$2,$3}'
    exit
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

command_check sed awk grep auditctl systemctl

if [[ ${1:-} == "-h" ]]; then usage; fi

# main
# ============================== **账号安全** ==============================
hr
checkitem **账号安全** 空口令账号
_result=$(awk -F: '$2==""' /etc/shadow)
if [[ -n $_result ]]; then
    checkitem_warn
    #echo "存在空口令账号"
    if [[ $OUTPUT_DETAIL == "yes" ]]; then
        echo "{{{ 问题详情"
        echo "$_result" | grep --color "^${_result%%:*}"
        echo "}}}"
    fi
    if [[ $OUTPUT_ADVISE == "yes" ]]; then
        echo "{{{ 修复建议"
        echo "为空口令账号设置密码（passwd <username>）或锁定该账号（passwd -l <username>）"
        echo "}}}"
    fi
else checkitem_success; fi

hr
checkitem **账号安全** UID 为 0 的非 root 账号
_result=$(awk -F: -v IGNORECASE=1 '$1!="root"&&$3==0' /etc/passwd)
if [[ -n $_result ]]; then
    checkitem_warn
    #echo "存在 UID 为 0 的非 root 账号"
    if [[ $OUTPUT_DETAIL == "yes" ]]; then
        echo "{{{ 问题详情"
        echo "$_result" | grep --color "^${_result%%:*}"
        echo "}}}"
    fi
    if [[ $OUTPUT_ADVISE == "yes" ]]; then
        echo "{{{ 修复建议"
        echo "如果该账户不是自行创建的或者不是 root 重命名的，则应禁用该账号"
        echo "}}}"
    fi
else checkitem_success; fi

hr
checkitem **账号安全** 可登录账号
_result=$(sort -nk3 -t: /etc/passwd | grep -Eiv ":/(sbin/(nologin|shutdown|halt)|bin/(sync|false))$" || :)
if [[ -n $_result ]]; then
    checkitem_info
    if [[ $OUTPUT_DETAIL == "yes" ]]; then
        echo "{{{ 问题详情"
        echo "$_result"
        echo "}}}"
    fi
    if [[ $OUTPUT_ADVISE == "yes" ]]; then
        echo "{{{ 修复建议"
        echo "检查是否存在未知账号或无需登录权限的账号，如 MySQL 启动账号"
        echo "}}}"
    fi
fi

# ============================== **系统配置** ==============================
hr
checkitem **系统配置** 是否关闭 Core Dump
_result=$(ulimit -c)
if [[ $_result -ne 0 ]]; then
    checkitem_warn
    #echo "Core Dump 设置不符合基线配置"
    if [[ $OUTPUT_DETAIL == "yes" ]]; then
        echo "{{{ 问题详情"
        echo "$_result"
        echo "}}}"
    fi
    if [[ $OUTPUT_ADVISE == "yes" ]]; then
        echo "{{{ 修复建议"
        echo "修改配置文件 /etc/security/limits.conf，设置 * soft core 0 及 * hard core 0"
        echo "}}}"
    fi
else checkitem_success; fi

# ============================== **环境配置** ==============================
hr
checkitem **环境配置** 检查 PATH 变量是否包含当前目录
_result=$(echo $PATH | grep -Eo '(^|:)(\.|:|$)' || :)
if [[ -n $_result ]]; then
    checkitem_warn
    #echo "PATH 变量存在异常"
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

hr
checkitem **环境配置** 检查 PATH 变量是否包含权限异常目录
_result=$(find $(echo ${PATH//:/ }) -type d -perm -777 2> /dev/null || :)
if [[ -n $_result ]]; then
    checkitem_warn
    #echo "PATH 变量包含权限异常目录"
    if [[ $OUTPUT_DETAIL == "yes" ]]; then
        echo "{{{ 问题详情"
        echo "$_result"
        echo "}}}"
    fi
    if [[ $OUTPUT_ADVISE == "yes" ]]; then
        echo "{{{ 修复建议"
        echo "设置目录为正常权限，从 PATH 中移除可疑目录"
        echo "}}}"
    fi
else checkitem_success; fi

# ============================== **密码策略** ==============================
hr
checkitem **密码策略** 密码最大过期天数
_string="PASS_MAX_DAYS $PASS_MAX_DAYS"
_result=$(awk -v IGNORECASE=1 '/^\s*PASS_MAX_DAYS/{print$2}' /etc/login.defs)
if [[ $_result -gt $PASS_MAX_DAYS || -z $_result ]]; then
    checkitem_warn
    #echo "PASS_MAX_DAYS 设置不符合基线配置"
    if [[ $OUTPUT_DETAIL == "yes" ]]; then
        echo "{{{ 问题详情"
        awk -v IGNORECASE=1 '/^\s*PASS_MAX_DAYS/' /etc/login.defs
        echo "}}}"
    fi
    if [[ $OUTPUT_ADVISE == "yes" ]]; then
        echo "{{{ 修复建议"
        echo "修改配置文件 /etc/login.defs，设置 PASS_MAX_DAYS 小于或等于 $PASS_MAX_DAYS。"
        echo "}}}"
    fi
    if [[ $BASELINE_APPLY == "yes" ]]; then
        echo "{{{ 基线加固"
        echo "#**密码策略** 密码最大过期天数" >> $BASELINE_RESTORE_FILE
        _result=$(sed -nr "/^\s*PASS_MAX_DAYS/p" /etc/login.defs)
        if [[ -n $_result ]]; then
            sed -ir "/^\s*PASS_MAX_DAYS/c $_string" /etc/login.defs
            echo "sed -ir \"/^\s*PASS_MAX_DAYS/c $_result\" /etc/login.defs" >> $BASELINE_RESTORE_FILE
        else
            sed -ir "$ a $_string" /etc/login.defs
            echo "sed -ir \"/^\s*PASS_MAX_DAYS/d\" /etc/login.defs" >> $BASELINE_RESTORE_FILE
        fi
        _result=$(sed -nr "/^\s*PASS_MAX_DAYS/p" /etc/login.defs)
        echo $_result
        echo "}}}"
    fi
else checkitem_success; fi

hr
checkitem **密码策略** 密码最小长度
_string="PASS_MIN_LEN $PASS_MIN_LEN"
_result=$(awk -v IGNORECASE=1 '/^\s*PASS_MIN_LEN/{print$2}' /etc/login.defs)
if [[ $_result -lt $PASS_MIN_LEN || -z $_result ]]; then
    checkitem_warn
    #echo "PASS_MIN_LEN 设置不符合基线配置"
    if [[ $OUTPUT_DETAIL == "yes" ]]; then
        echo "{{{ 问题详情"
        awk -v IGNORECASE=1 '/^\s*PASS_MIN_LEN/' /etc/login.defs
        echo "}}}"
    fi
    if [[ $OUTPUT_ADVISE == "yes" ]]; then
        echo "{{{ 修复建议"
        echo "修改配置文件 /etc/login.defs，设置 PASS_MIN_LEN 大于或等于 8。"
        echo "}}}"
    fi
    if [[ $BASELINE_APPLY == "yes" ]]; then
        echo "{{{ 基线加固"
        echo "#**密码策略** 密码最小长度" >> $BASELINE_RESTORE_FILE
        _result=$(sed -nr "/^\s*PASS_MIN_LEN/p" /etc/login.defs)
        if [[ -n $_result ]]; then
            sed -ir "/^\s*PASS_MIN_LEN/c $_string" /etc/login.defs
            echo "sed -ir \"/^\s*PASS_MIN_LEN/c $_result\" /etc/login.defs" >> $BASELINE_RESTORE_FILE
        else
            sed -ir "$ a $_string" /etc/login.defs
            echo "sed -ir \"/^\s*PASS_MIN_LEN/d\" /etc/login.defs" >> $BASELINE_RESTORE_FILE
        fi
        _result=$(sed -nr "/^\s*PASS_MIN_LEN/p" /etc/login.defs)
        echo $_result
        echo "}}}"
    fi
else checkitem_success; fi

# ============================== **SSH 安全** ==============================
hr
checkitem **SSH 安全** 是否允许空口令登录
_string="PermitEmptyPasswords no"
_result=$(grep -Ei "^\s*PermitEmptyPasswords\s+yes" /etc/ssh/sshd_config || :)
if [[ -n $_result ]]; then
    checkitem_warn
    #echo "PermitEmptyPasswords 设置不符合基线配置"
    if [[ $OUTPUT_DETAIL == "yes" ]]; then
        echo "{{{ 问题详情"
        echo "$_result"
        echo "}}}"
    fi
    if [[ $OUTPUT_ADVISE == "yes" ]]; then
        echo "{{{ 修复建议"
        echo "1. 修改配置文件 /etc/ssh/sshd_config，设置 PermitEmptyPasswords no 以禁止空口令登录"
        echo "2. 重启 sshd 服务"
        echo "}}}"
    fi
    if [[ $BASELINE_APPLY == "yes" ]]; then
        echo "{{{ 基线加固"
        echo "#**SSH 安全** 是否允许空口令登录" >> $BASELINE_RESTORE_FILE
        _result=$(sed -nr "/^\s*PermitEmptyPasswords/p" /etc/ssh/sshd_config)
        if [[ -n $_result ]]; then
            sed -ir "/^\s*PermitEmptyPasswords/c $_string" /etc/ssh/sshd_config
            echo "sed -ir \"/^\s*PermitEmptyPasswords/c $_result\" /etc/ssh/sshd_config" >> $BASELINE_RESTORE_FILE
        else
            sed -ir "$ a $_string" /etc/ssh/sshd_config
            echo "sed -ir \"/^\s*PermitEmptyPasswords/d\" /etc/ssh/sshd_config" >> $BASELINE_RESTORE_FILE
        fi
        _result=$(sed -nr "/^\s*PermitEmptyPasswords/p" /etc/ssh/sshd_config)
        echo $_result
        # TODO 判断 OS
        post_command="systemctl restart sshd"
        $post_command
        echo "$post_command" >> $BASELINE_RESTORE_FILE
        echo "}}}"
    fi
else checkitem_success; fi

hr
checkitem **SSH 安全** 是否允许 root 登录
_string="PermitRootLogin prohibit-password"
_result=$(grep -Ei "^\s*PermitRootLogin\s+[^y]+" /etc/ssh/sshd_config || :)
if [[ -z $_result ]]; then
    checkitem_warn
    #echo "PermitRootLogin 设置不符合基线配置"
    if [[ $OUTPUT_DETAIL == "yes" ]]; then
        echo "{{{ 问题详情"
        echo "当前配置允许 root 通过密码登录 SSH"
        echo "}}}"
    fi
    if [[ $OUTPUT_ADVISE == "yes" ]]; then
        echo "{{{ 修复建议"
        echo "1. 修改配置文件 /etc/ssh/sshd_config，设置 PermitRootLogin prohibit-password（将禁用密码登录，但仍可通过密钥进行验证）"
        echo "2. 重启 sshd 服务"
        echo "}}}"
    fi
    if [[ $BASELINE_APPLY == "yes" ]]; then
        echo "{{{ 基线加固"
        echo "#**SSH 安全** 是否允许 root 登录" >> $BASELINE_RESTORE_FILE
        _result=$(sed -nr "/^\s*PermitRootLogin/p" /etc/ssh/sshd_config)
        if [[ -n $_result ]]; then
            sed -ir "/^\s*PermitRootLogin/c $_string" /etc/ssh/sshd_config
            echo "sed -ir \"/^\s*PermitRootLogin/c $_result\" /etc/ssh/sshd_config" >> $BASELINE_RESTORE_FILE
        else
            sed -ir "$ a $_string" /etc/ssh/sshd_config
            echo "sed -ir \"/^\s*PermitRootLogin/d\" /etc/ssh/sshd_config" >> $BASELINE_RESTORE_FILE
        fi
        _result=$(sed -nr "/^\s*PermitRootLogin/p" /etc/ssh/sshd_config)
        echo $_result
        # TODO 判断 OS
        post_command="systemctl restart sshd"
        $post_command
        echo "$post_command" >> $BASELINE_RESTORE_FILE
        echo "}}}"
    fi
else checkitem_success; fi

hr
checkitem **SSH 安全** 禁用 UseDNS
_string="UseDNS no"
_result=$(grep -Ei "^\s*UseDNS\s+[^y]+" /etc/ssh/sshd_config || :)
if [[ -z $_result ]]; then
    checkitem_warn
    if [[ $OUTPUT_DETAIL == "yes" ]]; then
        echo "{{{ 问题详情"
        echo "当前配置下 sshd 将对远程主机名进行反向解析，以检查此主机名是否与其IP地址真实对应。（会增加登录耗时）"
        echo "}}}"
    fi
    if [[ $OUTPUT_ADVISE == "yes" ]]; then
        echo "{{{ 修复建议"
        echo "1. 修改配置文件 /etc/ssh/sshd_config，设置 UseDNS no"
        echo "2. 重启 sshd 服务"
        echo "}}}"
    fi
    if [[ $BASELINE_APPLY == "yes" ]]; then
        echo "{{{ 基线加固"
        echo "#**SSH 安全** UseDNS" >> $BASELINE_RESTORE_FILE
        _result=$(sed -nr "/^\s*UseDNS/p" /etc/ssh/sshd_config)
        if [[ -n $_result ]]; then
            sed -ir "/^\s*UseDNS/c $_string" /etc/ssh/sshd_config
            echo "sed -ir \"/^\s*UseDNS/c $_result\" /etc/ssh/sshd_config" >> $BASELINE_RESTORE_FILE
        else
            sed -ir "$ a $_string" /etc/ssh/sshd_config
            echo "sed -ir \"/^\s*UseDNS/d\" /etc/ssh/sshd_config" >> $BASELINE_RESTORE_FILE
        fi
        _result=$(sed -nr "/^\s*UseDNS/p" /etc/ssh/sshd_config)
        echo $_result
        # TODO 判断 OS
        post_command="systemctl restart sshd"
        $post_command
        echo "$post_command" >> $BASELINE_RESTORE_FILE
        echo "}}}"
    fi
else checkitem_success; fi

# ============================== **文件权限** ==============================
hr
checkitem **文件权限** 任何人都有写权限的文件
_result=$(find $(awk -v IGNORECASE=1 '$0~/^\s*[^#]/&&$2!="swap"{print$2}' /etc/fstab) -xdev -type f \( -perm -0002 -a ! -perm -1000 \))
if [[ -n $_result ]]; then
    checkitem_warn
    #echo "存在任何人都有写权限的文件"
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

hr
checkitem **文件权限** 任何人都有写权限的目录
_result=$(find $(awk -v IGNORECASE=1 '$0~/^\s*[^#]/&&$2!="swap"{print$2}' /etc/fstab) -xdev -type d \( -perm -0002 -a ! -perm -1000 \))
if [[ -n $_result ]]; then
    checkitem_warn
    #echo "存在任何人都有写权限的目录"
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

hr
checkitem **文件权限** 检查没有属主或属组的文件
_result=$(find $(awk -v IGNORECASE=1 '$0~/^\s*[^#]/&&$2!="swap"{print$2}' /etc/fstab) -xdev -nouser -o -nogroup)
if [[ -n $_result ]]; then
    checkitem_warn
    #echo "存在没有属主或属组的文件"
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

hr
checkitem **文件权限** 检查可疑隐藏文件
_result=$(find $(awk -v IGNORECASE=1 '$0~/^\s*[^#]/&&$2!="swap"{print$2}' /etc/fstab) -xdev -name ".. *" -o -name "...*")
if [[ -n $_result ]]; then
    checkitem_warn
    #echo "存在可疑隐藏文件"
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

hr
checkitem **文件权限** 检查 SUID/SGID 文件
_result=$(find $(awk -v IGNORECASE=1 '$0~/^\s*[^#]/&&$2!="swap"{print$2}' /etc/fstab) -xdev \( -perm -4000 -o -perm -2000 \))
if [[ -n $_result ]]; then
    checkitem_warn
    #echo "存在可疑 SUID/SGID 文件"
    if [[ $OUTPUT_DETAIL == "yes" ]]; then
        echo "{{{ 问题详情"
        for i in $_result; do
            if [[ ! ${SUID_SGID_FILES[@]} =~ "$i" ]]; then
                echo $i
            fi
        done
        echo "}}}"
    fi
    if [[ $OUTPUT_ADVISE == "yes" ]]; then
        echo "{{{ 修复建议"
        echo "检查输出文件/目录权限是否异常"
        echo "}}}"
    fi
else checkitem_success; fi

# ============================== **日志审计** ==============================
hr
checkitem **日志审计** 是否开启安全日志
_string="authpriv.* /var/log/secure"
_result=$(grep -Ei "^\s*authpriv\." /etc/rsyslog.conf || :)
if [[ -z $_result ]]; then
    checkitem_warn
    #echo "authpriv.* 设置不符合基线配置"
    if [[ $OUTPUT_DETAIL == "yes" ]]; then
        echo "{{{ 问题详情"
        echo "未配置 authpriv.*"
        echo "}}}"
    fi
    if [[ $OUTPUT_ADVISE == "yes" ]]; then
        echo "{{{ 修复建议"
        echo "修改配置文件 /etc/rsyslog.conf，设置 authpriv.* /var/log/secure"
        echo "}}}"
    fi
else checkitem_success; fi

hr
checkitem **日志审计** 是否加载日志审计内核模块
_result=$(auditctl -s | awk '/^enabled/{print$2}')
if [[ $_result -ne 1 ]]; then
    checkitem_warn
    #echo "未加载日志审计内核模块"
    if [[ $OUTPUT_DETAIL == "yes" ]]; then
        echo "{{{ 问题详情"
        auditctl -s | awk '/^enabled/'
        echo "}}}"
    fi
    if [[ $OUTPUT_ADVISE == "yes" ]]; then
        echo "{{{ 修复建议"
        echo "执行命令 auditctl -e 1 启用日志审计内核模块"
        echo "}}}"
    fi
else checkitem_success; fi

hr
checkitem **日志审计** 是否开启日志审计服务
_result=$(systemctl status auditd | grep "active (running)" || :)
if [[ -z $_result ]]; then
    checkitem_warn
    #echo "未开启日志审计服务"
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

hr
checkitem **日志审计** 是否开启 cron 守护进程日志
_result=$(grep -Ei "^\s*cron\." /etc/rsyslog.conf || :)
if [[ -z $_result ]]; then
    checkitem_warn
    #echo "cron.* 设置不符合基线配置"
    if [[ $OUTPUT_DETAIL == "yes" ]]; then
        echo "{{{ 问题详情"
        echo "未配置 cron.*"
        echo "}}}"
    fi
    if [[ $OUTPUT_ADVISE == "yes" ]]; then
        echo "{{{ 修复建议"
        echo "修改配置文件 /etc/rsyslog.conf，设置 cron.* /var/log/cron"
        echo "}}}"
    fi
else checkitem_success; fi

# ============================== **网络配置** ==============================
hr
checkitem **网络配置** 是否允许 ping 请求
# sysctl net.ipv4.icmp_echo_ignore_all | awk '{print$3}'
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
        echo "1. 修改配置文件 /etc/sysctl.conf，设置 net.ipv4.icmp_echo_ignore_all = 0"
        echo "2. 执行命令：sysctl net.ipv4.icmp_echo_ignore_all=0"
        #echo "执行命令：echo "0" > /proc/sys/net/ipv4/icmp_echo_ignore_all"
        echo "}}}"
    fi
else checkitem_success; fi

