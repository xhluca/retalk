// retalk.dev — asciinema-player embedding, after agent-talk's players.js
// pattern (agent-talk.pages.dev). Instantiates the locally vendored player
// from data-* attributes; no external calls at runtime.
//
//   data-cast="assets/casts/x.cast"  (required) local path to the .cast file
//   data-speed="1.4"                 playback speed
//   data-idle="2"                    idleTimeLimit seconds
//   data-sync-group="name"           lockstep group: members start together
//                                    and, when every member has ended, all
//                                    seek to 0 and replay together, so the
//                                    loop never accumulates drift. Members
//                                    never self-loop. The casts in a group
//                                    must share the same total duration.
//
// Playback starts when the players scroll into view and pauses off-screen.

(function () {
  "use strict";

  function mount(el) {
    if (!window.AsciinemaPlayer || !el.dataset.cast) return null;
    return window.AsciinemaPlayer.create(el.dataset.cast, el, {
      fit: "width",
      loop: false,               // groups are replayed by the controller
      controls: false,
      autoPlay: false,           // play/pause is driven below
      idleTimeLimit: parseFloat(el.getAttribute("data-idle") || "2"),
      speed: parseFloat(el.getAttribute("data-speed") || "1"),
      theme: "asciinema",
      poster: "npt:0:01"
    });
  }

  function ready(fn) {
    if (document.readyState !== "loading") fn();
    else document.addEventListener("DOMContentLoaded", fn);
  }

  ready(function () {
    var entries = Array.prototype.slice.call(
      document.querySelectorAll(".player[data-cast]")
    ).map(function (el) {
      return { el: el, player: mount(el), started: false, visible: false,
               group: el.getAttribute("data-sync-group") || null };
    });

    var groups = {};
    entries.forEach(function (e) {
      if (!e.group || !e.player) return;
      (groups[e.group] = groups[e.group] || []).push(e);
    });

    function playGroup(members) {
      members.forEach(function (m) {
        try { m.player.play(); m.started = true; } catch (_) {}
      });
    }

    Object.keys(groups).forEach(function (name) {
      var members = groups[name];
      var ended = 0;
      members.forEach(function (m) {
        m.player.addEventListener("ended", function () {
          ended += 1;
          if (ended >= members.length) {
            ended = 0;
            members.forEach(function (x) {
              try { x.player.seek(0); } catch (_) {}
            });
            if (members.some(function (x) { return x.visible; })) {
              playGroup(members);
            }
          }
        });
      });
    });

    function playEntry(e) {
      if (e.group) playGroup(groups[e.group]);
      else { try { e.player.play(); e.started = true; } catch (_) {} }
    }

    function pauseEntry(e) {
      if (e.group) {
        if (!groups[e.group].some(function (m) { return m.visible; })) {
          groups[e.group].forEach(function (m) {
            try { m.player.pause(); } catch (_) {}
          });
        }
      } else {
        try { e.player.pause(); } catch (_) {}
      }
    }

    if ("IntersectionObserver" in window) {
      var io = new IntersectionObserver(function (obs) {
        obs.forEach(function (entry) {
          var rec = entries.filter(function (e) {
            return e.el === entry.target;
          })[0];
          if (!rec || !rec.player) return;
          rec.visible = entry.isIntersecting;
          if (entry.isIntersecting) playEntry(rec);
          else if (rec.started) pauseEntry(rec);
        });
      }, { threshold: 0.4 });
      entries.forEach(function (e) { io.observe(e.el); });
    } else {
      entries.forEach(function (e) { if (e.player) playEntry(e); });
    }
  });
})();
