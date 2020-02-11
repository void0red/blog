---
title: remote control transmission
date: 2018-03-17
tags: others
---

> 设备：`树莓派3B` 系统：`LEDE 4.4.92`

1. 下载安装`transmission-cli-openssl` `transmission-daemon-openssl` `transmission-remote-openssl` `transmission-web` `luci-app-transmission` `luci-i18n-transmission-zh-cn`

2. 配置transmission

   直接在网页配置，或者使用配置文件`/etc/config/transmisson`
<!-- more -->
   ```
   config transmission
           option config_dir '/tmp/transmission'
           option mem_percentage '50'
           option nice '10'
           option ionice_flags '-c 3'
           option alt_speed_enabled 'false'
           option bind_address_ipv4 '0.0.0.0'
           option bind_address_ipv6 '::'
           option blocklist_enabled 'true'
           option cache_size_mb '2'
           option download_queue_enabled 'true'
           option download_queue_size '4'
           option encryption '1'
           option lazy_bitfield_enabled 'true'
           option lpd_enabled 'false'
           option message_level '1'
           option peer_limit_global '240'
           option peer_limit_per_torrent '60'
           option peer_port '51413'
           option peer_port_random_on_start 'false'
           option peer_socket_tos 'default'
           option pex_enabled 'true'
           option port_forwarding_enabled 'true'
           option preallocation '1'
           option queue_stalled_enabled 'true'
           option queue_stalled_minutes '30'
           option ratio_limit_enabled 'false'
           option rpc_authentication_required '远程访问控制'
           option rpc_username '远程访问用户名'
           option rpc_password '远程访问密码'
           option rpc_bind_address '0.0.0.0'
           option rpc_enabled '是否打开远程访问'
           option rpc_port '远程访问端口'
           option rpc_url '/transmission/'
           option scrape_paused_torrents_enabled 'true'
           option script_torrent_done_enabled 'false'
           option speed_limit_down_enabled 'false'
           option speed_limit_up_enabled 'false'
           option trash_original_torrent_files 'false'
           option umask '18'
           option upload_slots_per_torrent '14'
           option utp_enabled 'true'
           option scrape_paused_torrents 'true'
           option watch_dir_enabled 'false'
           option download_dir '下载目录'
           option rename_partial_files 'false'
           option seed_queue_enabled 'true'
           option incomplete_dir_enabled '启用未完成目录'
           option incomplete_dir '未完成目录'
           option enabled '1'
           option start_added_torrents 'false'
           option rpc_whitelist_enabled 'false'
           option dht_enabled 'false'
           option idle_seeding_limit_enabled 'false'
           option blocklist_url 'URL阻止列表'
   ```

   > 这个时候应该可以通过内网ip加port在浏览器访问到transmission的管理页面了

3. 内网穿透

    使用[frp](https://github.com/fatedier/frp)进行内网穿透，详细配置见官方文档，唯一需要注意的是如果配置到`custom_domains`选项（不出意外的话），如果是没有解析的ip直接填写ip，这样才能通过ip打开（真是恶心），外网服务端可以使用`nohup &`或者`screen`将其置于后台运行，内网客户端可以添加开机自启动项（学校每晚断电233

   ！！！切记不要在断电的边缘下载种子，可能造成内存卡`read only`，解决方法自行百度。

   > 这个时候应该可以通过外网ip加port在浏览器访问到transmission的管理页面了
4. 手机客户端

   GitHub上有个transmission的开源手机客户端（Android）

   下载地址： https://github.com/urandom/gearshift/releases

   配置很容易