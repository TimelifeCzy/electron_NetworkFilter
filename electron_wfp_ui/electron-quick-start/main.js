const { app, BrowserWindow } = require('electron')
const { ipcMain, ipcRenderer } = require('electron');
const path = require('path')

let mainWin = null;

function m_createWin(){
  mainWin = new BrowserWindow({
    width: 1200,
    height: 700,
    maxWidth: 1300,
    maxHeight: 700,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: true,
      contextIsolation: false,
      enableRemoteModul: true,
    }
  }) 

  require('./menu.js');

  mainWin.loadURL(path.join(__dirname, "./index.html"));
  mainWin.webContents.openDevTools();
}

ipcMain.on('IpcMain_updata_table', (event, arg) => {
  console.log("[+] Main.js recv to winMsg");
  event.sender.send('ipcRenderer_table_addLine', arg);
});


app.on('ready', () =>{
  m_createWin();
})