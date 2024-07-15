import random
import re
import uinput
import time
from PIL import ImageGrab
import pyocr
import pyocr.builders

#初始化虚拟键盘
keys = [
    uinput.KEY_A,uinput.KEY_D,uinput.KEY_F,uinput.KEY_I,uinput.KEY_J,uinput.KEY_K,uinput.KEY_O,uinput.KEY_R,uinput.KEY_S,uinput.KEY_T,uinput.KEY_U,uinput.KEY_V,uinput.KEY_W,uinput.KEY_X,uinput.KEY_Y,uinput.KEY_Z,
    uinput.KEY_ENTER,uinput.KEY_LEFTALT,uinput.KEY_TAB
]
device = uinput.Device(keys)
ab = ['a','d','f','i','j','k','o','r','s','t','u','v','w','x','y','z']

#配置pyocr
tool = pyocr.get_available_tools()[0]
lang = "eng"
block = (235,235,1800,600)  #指定输入框位置

#生成测试数据
length = 1000
inputkeys = []
key = ''
for i in range(length):
    x = random.randint(0,len(ab)-1)
    inputkeys.append(keys[x])
    key = key + ab[x]

#切换并输入测试数据
time.sleep(1)
device.emit_combo([uinput.KEY_LEFTALT,uinput.KEY_TAB])
time.sleep(1)
st = time.time()
for i in range(length):
    device.emit_click(inputkeys[i])
    time.sleep(0.01)
device.emit_combo([uinput.KEY_LEFTALT,uinput.KEY_TAB])

#检测是否显示完成
txt = ''
while txt != key:
    img = ImageGrab.grab(block)
    txt = tool.image_to_string(
        img,
        lang=lang,
        builder=pyocr.builders.TextBuilder()
    )
    txt = "".join(filter(str.isalpha, txt))
print((time.time()-st)/length)