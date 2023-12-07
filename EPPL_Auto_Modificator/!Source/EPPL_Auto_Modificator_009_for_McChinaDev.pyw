import wx
import sys
import os

class MyFrame(wx.Frame):
    def __init__(self):
        super().__init__(parent=None, title='EPPL_Auto_Modificator', size=(350, 200))
        self.filename = os.path.join('..','!McChinaDev','unpacked_Minecraft.Windows.exe')
        # остальной код
        self.panel = wx.Panel(self)
        self.checkbox = wx.CheckBox(self.panel, label='Enable/Disable the EPPL Mod', pos=(10, 10))
        self.checkbox.Bind(wx.EVT_CHECKBOX, self.on_checkbox_toggle)
        static_text = wx.StaticText(self.panel, label='Developed by MaxRM for MDLC', pos=(10, 140))
        # Чтение информации из файла конфигурации
        with open('config.txt', 'r') as config_file:
            lines = config_file.readlines()
            self.config_data = [line.strip().split(' >> ') for line in lines]

        # Преобразование строк в целые числа и шестнадцатеричные значения
        for i in range(len(self.config_data)):
            self.config_data[i][0] = int(self.config_data[i][0], 16)
            self.config_data[i][1:] = [value.strip() for value in self.config_data[i][1:]]

        self.update_checkbox_state()

    # Метод обновления состояния флажка
    def update_checkbox_state(self):
        with open(self.filename, 'rb') as file:
            file.seek(self.config_data[0][0])
            hex_value1 = file.read(1).hex().upper()
            file.seek(self.config_data[1][0])
            hex_value2 = file.read(1).hex().upper()
            if hex_value1 == self.config_data[0][2] and hex_value2 == self.config_data[1][2]:
                self.checkbox.SetValue(True)
            elif hex_value1 == self.config_data[0][1] and hex_value2 == self.config_data[1][1]:
                self.checkbox.SetValue(False)
            else:
                self.checkbox.Disable()
                wx.MessageBox("Error: Invalid values found", "Error", style=wx.OK | wx.ICON_ERROR)
                self.Close()

    def replace_hex(self, hex_value):
        with open(self.filename, 'rb+') as file:
            file.seek(self.config_data[0][0])
            file.write(bytes.fromhex(hex_value))
            file.seek(self.config_data[1][0])
            file.write(bytes.fromhex(hex_value))
            file.flush()

    def on_checkbox_toggle(self, event):
        if self.checkbox.GetValue():
            self.replace_hex(self.config_data[0][2])
        else:
            self.replace_hex(self.config_data[0][1])
        self.update_checkbox_state()

app = wx.App()
frame = MyFrame()
frame.Show()
app.MainLoop()