const {
    Menu
} = require('electron')
const template = [
    {
        label: '关于作者'
    },
    {
        label: '插件',
        submenu: [{
            label: '爆破',
            submenu: [{
                label: '字典爆破(导入)'
            }, {
                label: '在线爆破'
            }]
        }, {
            label: '自动化检测'
        }]
    },
]
 
var list = Menu.buildFromTemplate(template)
Menu.setApplicationMenu(list)