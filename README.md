# <p align="center">ChatWith</p>

<p align="center">使用您的API Key与Deepseek聊天</p>

---

## 特点

- 支持加密储存秘钥

- EFS加密秘钥

> [!WARNING] 
> EFS加密仍在测试中！如非必要，请不要使用这个方案！

- 可通过命令修改API端点

- ~~其实没啥特点~~

## 使用

1. 从Release下载最新版本

2. 首次运行：程序会要求输入DeepSeek API密钥并选择存储方式，当前支持的加密方式见下：

- 不使用加密（不安全，不推荐）

> [!WARNING]
> 如果不使用加密，你的API秘钥将明文存储在同一目录的api_key.txt文件中

- 使用自定义密码加密秘钥

> [!NOTE]
> 自定义密码加密使用 **AES-256-CBC** 加密

- 使用Windows EFS加密秘钥（实验性，不推荐）

> [!CAUTION]
> EFS加密仍在开发中，属于实验性产品
>
> 不要使用此方案除非你有勇气

3. 当提示 *DeepSeek对话系统已就绪（输入/exit退出）* 时，你就可以开始聊天了

### 命令

在正式进入对话后，您可以以```/```开头，将当前语句作为命令提交

当前可用的命令及其用法见下：

- ```/about``` 展示程序信息

- ```/exit``` 退出程序

- ```/confirm``` 确认待处理的操作

- ```/api show```显示API密钥

- ```/api set``` 设置新API密钥

- ```/api clear``` 清除存储的API密钥

- ```/model list``` 列出可用模型

- ```/model set <模型名称>``` 设置使用的模型

- ```/env list``` 列出环境变量

- ```/env set <键> <值>``` 设置环境变量

## Installing from the repository

1. Clone the repository

```
git clone git@github.com:NaOH-HaN/ChatWith.git
```

2. Install requirements

```
pip install -r requirements.txt
```

3. Run main.py

```
py src/main.py
```

## 开源说明

Copyright © 2025 NaOH_HaN

Licensed under the Apache License, Version 2.0 (the "License");

You may not use this file except in compliance with the License.

## Additional Notes

This program was developed with the help of **Deepseek R1**.

90% of the code was written by Deepseek R1.

Of course, some magical bugs need to be fixed manually

Thanks to AI, I was provided with a few sessions to learn the code quickly. Although, I am still a newbie

## Thanks

This product includes software developed by:

- Requests (https://github.com/psf/requests)
  Copyright 2019 Kenneth Reitz

- cryptography (https://github.com/pyca/cryptography)
  Copyright (c) Individual contributors
  Licensed under Apache License 2.0 and BSD 3-Clause License

You can also find these in NOTICE
