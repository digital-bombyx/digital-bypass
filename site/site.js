// digital-bypass — сайт. Всё здесь — украшения: без JS страница полностью читается.
document.documentElement.classList.add("js");

// 1. «Стена» запрещённых сайтов на первом экране (декор, aria-hidden).
const DOMAINS = [
  "youtube.com", "discord.com", "x.com", "instagram.com", "rutracker.org", "linkedin.com",
  "facebook.com", "medium.com", "soundcloud.com", "twitch.tv", "chatgpt.com", "patreon.com",
  "torproject.org", "signal.org", "proton.me", "github.io", "notion.so", "cloudflare.com",
  "googlevideo.com", "spotify.com", "reddit.com", "telegram.org", "whatsapp.com", "viber.com",
];
const wall = document.querySelector(".wall");
if (wall) {
  // Перемешиваем по-своему для каждой строки, чтобы стена не выглядела повтором.
  const line = (seed) => {
    const a = [...DOMAINS];
    for (let i = a.length - 1; i > 0; i--) {
      seed = (seed * 9301 + 49297) % 233280;
      const j = Math.floor((seed / 233280) * (i + 1));
      [a[i], a[j]] = [a[j], a[i]];
    }
    return a.map((d) => `<span>${d}</span>`).join(" · ");
  };
  const html = Array.from({ length: 22 }, (_, i) => `<p>${line(i + 7)}</p>`).join("");
  wall.querySelectorAll(".wall-layer").forEach((l) => (l.innerHTML = html));

  // «Фонарик»: под курсором сквозь чёрные плашки проступают имена сайтов.
  const hero = document.getElementById("hero");
  if (hero && matchMedia("(pointer: fine)").matches) {
    let rect = hero.getBoundingClientRect();
    new ResizeObserver(() => (rect = hero.getBoundingClientRect())).observe(hero);
    addEventListener("scroll", () => (rect = hero.getBoundingClientRect()), { passive: true });
    hero.addEventListener("pointermove", (e) => {
      // В пикселях от угла блока: маска лежит ровно на нём, без поворота и растяжения.
      hero.style.setProperty("--mx", `${e.clientX - rect.left}px`);
      hero.style.setProperty("--my", `${e.clientY - rect.top}px`);
    });
  }
}

// 2. Плашки цензуры в заголовках стираются, когда заголовок отошёл от нижнего края примерно на 15% экрана.
const redacted = document.querySelectorAll(".r-scroll");
if (redacted.length && "IntersectionObserver" in window) {
  const io = new IntersectionObserver(
    (entries) => {
      for (const e of entries) {
        if (e.isIntersecting) {
          e.target.classList.add("unveiled");
          io.unobserve(e.target);
        }
      }
    },
    // срабатывает, когда слово целиком в верхних 85% экрана
    { rootMargin: "0px 0px -15% 0px", threshold: 1 },
  );
  redacted.forEach((el) => io.observe(el));
} else {
  redacted.forEach((el) => el.classList.add("unveiled"));
}

// 3. Лесенка задержек для браузеров без sibling-index().
if (!CSS.supports("animation-delay: calc(sibling-index() * 0.1s)")) {
  document.querySelectorAll(".term-lines").forEach((list) =>
    [...list.children].forEach((el, i) => el.style.setProperty("--sibling-index", i + 1)),
  );
}

// 4. Терминал начинает «печатать», когда попадает на экран.
const term = document.querySelector(".term");
if (term && "IntersectionObserver" in window) {
  const io = new IntersectionObserver(
    (entries) => {
      if (entries.some((e) => e.isIntersecting)) {
        term.classList.add("play");
        io.disconnect();
      }
    },
    { threshold: 0.35 },
  );
  io.observe(term);
} else if (term) {
  term.classList.add("play");
}

// 5. Снимки открываются в <dialog>; без JS ссылка просто откроет картинку.
const box = document.getElementById("lightbox");
if (box && typeof box.showModal === "function") {
  const img = box.querySelector("img");
  const cap = box.querySelector(".lb-cap");
  document.querySelectorAll(".shot").forEach((a) => {
    a.addEventListener("click", (e) => {
      e.preventDefault();
      img.src = a.href;
      img.alt = a.querySelector("img").alt;
      cap.textContent = a.dataset.caption;
      box.showModal();
    });
  });
  // Закрытие по клику мимо снимка там, где closedby ещё не поддерживается.
  if (!("closedBy" in HTMLDialogElement.prototype)) {
    box.addEventListener("click", (e) => {
      if (e.target === box) box.close();
    });
  }
}
