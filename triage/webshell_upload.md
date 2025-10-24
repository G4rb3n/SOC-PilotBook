# Webshell上传研判

## 目标
判断webshell上传的告警是真实攻击，还是业务行为误报。

## 范围
webshell上传、文件上传、web后门、脚本上传、web目录写入、web文件创建、一句话木马上传相关安全告警

## 输入
${alert:name}: 告警名称
${alert:severity}: 告警等级
${alert:direction}: 告警访问方向
${alert:attackResult}: 攻击结果
${alert:httpRequest}: http请求内容
${alert:httpResponse}: http响应内容
${alert:filePath}: 告警文件路径

## 输出
${alert:triageResult}: 研判结果
${alert:triageCoT}: 研判思维链

## 工具
${soc-mcp}: ${soc-getAlert}, ${soc-getHttpLog}, ${soc-getAsset}
${edr-mcp}: ${edr-getFileContent}

## 流程
### 正报
1-1: 从${alert:httpRequest}或${alert:filePath}获取上传文件的名称，判断后缀名是否为.php、.asp、.aspx、.jsp、.jspx等常见web脚本文件后缀名，或.jpg、.jpeg、.png等常见图片马后缀名，尤其是.php.jpg、.asp.png等双后缀名
1-2: 从${alert:httpRequest}获取上传文件的内容，或通过${edr-getFileContent}异步获取文件的内容，判断文件内容是否包含eval、system、exec、shell_exec、passthru等常见webshell命令，是否包含payload、passkey、base64等常见webshell特征
2-1：通过${soc-getAlert}获取该目的IP近24小时的告警，判断是否有其他关联告警，如漏洞扫描、webshell通信等

### 误报
1-1： 通过${soc-getAsset}获取该目的IP的资产信息，判断是否为存在文件上传相关业务的服务器（如web应用服务器、文件服务器等），同时判断${alert:direction}是否为内对内
2-1：从${alert:httpRequest}或${alert:filePath}获取上传文件的名称，判断名称是否为常见的业务文件名（如index.php、config.php等），或者包含下划线等比较规范的业务文件名（如user_avatar.php、order_detail.php等）
2-2：从${alert:httpRequest}获取上传文件的内容，或通过${edr-getFileContent}异步获取文件的内容，判断文件内容是否常规的业务代码（包含大量注释、变量名称比较规范），或内容包含大部分乱码
3-1：通过${soc-getAlert}获取该目的IP近7天的告警，判断是否有多个相似告警，以及告警里的上传文件名格式是否也是一致的
4-1：通过${soc-getHttpLog}获取该目的IP近24小时的http请求日志，判断该url接口是否有其他相似的上传请求，以及上传文件名格式是否也是一致的