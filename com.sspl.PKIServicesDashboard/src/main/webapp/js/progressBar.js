/**
 * 
 */
function setProgress(p,elm) {
    var prg = document.getElementById(elm);
    prg.style.width = p+"px";
    prg.setAttribute("data-progress", p);
}

setProgress(10);