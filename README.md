# docker_nessus_unlimited
docker build nessus with unlimited ip

## prepare

https://www.tenable.com/downloads/nessus?loginAttempted=true

下载Nessus-8.13.1-debian6_amd64.deb

## docker

```
docker build --build-arg NESSUS_DEB=Nessus-8.13.1-debian6_amd64.deb -t nessus .

docker run -d -p 8834:8834 --name nessus nessus
```

- 构建docker镜像时会进行安装包自动下载和unlimited ip破解，所以会比较慢，请耐心等待。

- web登录xxcdd/xxcdd1996

## update plugin

```
docker exec -it nessus bash
python install.py update
sh run.sh
```



## refer

https://github.com/0xa-saline/Nessus_update

https://zhengshaoshaolin.blog.csdn.net/article/details/109488655

## notice

因为Nessus官网经常修改插件下载api，所以每隔一段时间自动化脚本会失效
