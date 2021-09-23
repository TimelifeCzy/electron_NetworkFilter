'use strict'

const ffi = require('ffi-napi');
const ref = require('ref-napi');
const refArray = require('ref-array-napi');
const Struct = require('ref-struct-napi');
const { watch } = require('original-fs');
const { ipcRenderer } = require('electron');

var timer_cout = 0;

// 这里结构体需要和DLL中元素反向定义
let IPPACKHADERNode = {
    reserv: ref.types.ulong,
    reserv1: ref.types.ulong,
    pid: ref.types.ulong,
    portocol: ref.types.ulong,
    localaddr: ref.types.ulong,
    localport: ref.types.ulong,
    remoteaddr: ref.types.ulong,
    remoteport: ref.types.ulong,
    heartbeat: ref.types.ulong
    //portocol: refArray(ref.types.char, 10),
};

const IPPACKHADER = Struct(IPPACKHADERNode);
let ippack = new IPPACKHADER();

const POINTER = ref.refType(ref.types.void);

// 加载DLL
const driverobj = ffi.Library("..\\windowdll\\x64\\WINDOWSDLL.dll",{
    'puLoadDriver': ['int',['string', 'int']],
    'puPipGetBuf': [ref.types.int, [POINTER, ref.refType(IPPACKHADER)]],
    'puPipInit': [POINTER, ['string']]
});

var PipHandle = driverobj.puPipInit("\\\\.\\Pipe\\uiport");
if(PipHandle)
{
    console.log("Connect Server Pip Success!");
}

function Fnsleep(numberMillis) {
    var now = new Date();
    var exitTime = now.getTime() + numberMillis;
    while (true) {
        now = new Date();
        if (now.getTime() > exitTime)
        return;
        }
}

function callback(){
    if(PipHandle)
    {
        // 函数阻塞等待
        var nRet = driverobj.puPipGetBuf(PipHandle, ippack.ref());
        console.log(ippack.pid);
        console.log(ippack.portocol);
        console.log(ippack.localaddr);
        console.log(ippack.localport);
        console.log(ippack.remoteaddr);
        console.log(ippack.remoteport);
        $table.append(testbuf);
    }
}

function start_PipRecv()
{
    const $table = window.$("#table_ip");
    var timehandle = window.setInterval(
        function(){ 
            if(PipHandle)
            {
                // 函数阻塞等待
                var nRet = driverobj.puPipGetBuf(PipHandle, ippack.ref());
                // 非心跳探测
                if(ippack.heartbeat == 998)
                {
                    var show_ipdata = "<tr>"
                    show_ipdata += "<td>";
                    show_ipdata += ippack.pid;
                    show_ipdata += "</td>";
                    show_ipdata += "<td>";
                    show_ipdata += ippack.portocol;
                    show_ipdata += "</td>";
                    show_ipdata += "<td>";
                    show_ipdata += ippack.localaddr;
                    show_ipdata += "</td>";
                    show_ipdata += "<td>";
                    show_ipdata += ippack.localport;
                    show_ipdata += "</td>";
                    show_ipdata += "<td>";
                    show_ipdata += ippack.remoteaddr;
                    show_ipdata += "</td>";
                    show_ipdata += "<td>";
                    show_ipdata += ippack.remoteport;
                    show_ipdata += "</td>";
                    show_ipdata += "</tr>";
                    console.log(show_ipdata);
                    $table.append(show_ipdata);
                }
            }
        }, 100);
    // if(1000 > timer_cout)
    // {
    //     timer_cout += 1;
    //     var timers = window.requestAnimationFrame(callback);
    // }
}

// 接收server发送来的消息处理
ipcRenderer.on('ipcRenderer_recv_updatetable', (event, arg) => {
    console.log(arg); // prints "pong"
}
);
  

