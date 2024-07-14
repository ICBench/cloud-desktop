# cloud-desktop
## delaytest.py使用
### 云侧
预先准备一张用于检测的纯色图片，例如本次使用的white.png，打开终端输入以下指令

```bash
eog -f white.png  #全屏打开white.png
```

然后保持终端位于云桌面最上层
### 端侧
首先需要获取需要检测的像素点位置，通过获取鼠标指向的像素点位置来间接获取。

```bash
xinput list  #找到鼠标对应的设备号
xinput query-state 10  #查询鼠标状态，10为前一条指令找到的鼠标的设备号，从中找到鼠标的坐标
```

在代码中修改检测像素点位置，接下来执行delaytest.py（注意由于使用了虚拟输入所以需要使用sudo权限），执行前需要保证当前窗口的下一个窗口是云桌面（即使用ALT+TAB后会切换到云桌面并且此时输入的键可以直接输入到云桌面内）

```bash
sudo python delaytest.py
```

执行完成后会输出一个浮点数表示延迟（单位：s）