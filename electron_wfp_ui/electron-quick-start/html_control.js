const { copyFileSync } = require("original-fs");

window.$('#ul_packinfo btn1').addClass('active').siblings().removeClass('active');

window.$('#ul_packinfo li').click(function () {
    window.$(this).addClass('active').siblings().removeClass('active')
    let id = window.$(this).attr('id');
    console.log(id)
    window.$('#div-group').find('#'+id+'_div').show().siblings().hide()
})

window.$("#table_ip tr").click(function(e) {
    var text = window.$(this).text();
    console.log(text)
});

// ui折叠
var count = 1;
window.$(document).ready(() => {
    window.$('ul.nav-sidebar>li').click(function (e) {
        let dang = window.$(window.$(this).find('ul'));
        let quan = window.$('ul.nav-sidebar>li>ul');
        if (dang[0].hasAttribute("style")) {
            dang.removeAttr("style");
            count--
            console.log("折叠当前项之后的count值:", count);
        } else {
            count++;
            if (count > 1) {
                quan.removeAttr("style");
                count = 0;
            }
            dang.attr("style", "display: block;")
            count++
            console.log("else最后一句的count:", count);
        }
    });
})