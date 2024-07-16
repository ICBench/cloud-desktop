import random
import re
import uinput
import time
from PIL import ImageGrab
import pyocr
import pyocr.builders

#初始化虚拟键盘
ALPHABET = [
    ('a',uinput.KEY_A),('d',uinput.KEY_D),('f',uinput.KEY_F),('i',uinput.KEY_I),('j',uinput.KEY_J),('k',uinput.KEY_K),('o',uinput.KEY_O),('r',uinput.KEY_R),('s',uinput.KEY_S),('t',uinput.KEY_T),('u',uinput.KEY_U),('v',uinput.KEY_V),('w',uinput.KEY_W),('x',uinput.KEY_X),('y',uinput.KEY_Y),('z',uinput.KEY_Z)
]

#配置pyocr
tool = pyocr.get_available_tools()[0]
lang = "eng"
block = (120,160,1800,600)  #指定输入框位置

#生成测试数据
length = 1000
keys_to_press = []
expected_txt = []
for _ in range(length):
    ch, key = random.choice(ALPHABET)
    keys_to_press.append(key)
    expected_txt.append(ch)
expected_txt = ''.join(expected_txt)

#切换并输入测试数据
with uinput.Device([x[1] for x in ALPHABET] + [uinput.KEY_ENTER,uinput.KEY_LEFTALT,uinput.KEY_TAB]) as device:
    time.sleep(1)
    device.emit_combo([uinput.KEY_LEFTALT,uinput.KEY_TAB])
    time.sleep(1)
    start = time.time()
    for key in keys_to_press:
        device.emit_click(key)
        time.sleep(0.01)
    device.emit_combo([uinput.KEY_LEFTALT,uinput.KEY_TAB])

#检测是否显示完成
txt = ''
while txt != expected_txt:
    img = ImageGrab.grab(block)
    txt = tool.image_to_string(
        img,
        lang=lang,
        builder=pyocr.builders.TextBuilder()
    )
    txt = "".join(filter(str.isalpha, txt))
print('%.1f kps' % (len(expected_txt) / (time.time()-start)))