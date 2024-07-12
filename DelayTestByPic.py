import time
import uinput
from PIL import ImageGrab

device = uinput.Device([
    uinput.KEY_LEFTALT,
    uinput.KEY_TAB,
    uinput.KEY_ENTER
])

time.sleep(1)
device.emit_combo([uinput.KEY_LEFTALT,uinput.KEY_TAB])  #模拟键盘输入切换窗口
time.sleep(1)
device.emit_click(uinput.KEY_ENTER)  #模拟输入回车
st = time.time()
p = (0,0,0)
while p != (255,255,255):  #检测是否为白色即RGB值为(255,255,255)
    scshot = ImageGrab.grab()  #获取当前屏幕
    p = scshot.getpixel((739,551))  #(739,551)为检测像素点位置，根据实际情况修改
ed = time.time()
print(ed-st)
