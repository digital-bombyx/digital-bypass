/** Бесплатные публичные подписки для Xray. Источник — igareck/vpn-configs-for-russia:
 *  серверы проверяются с сервера в России раз в несколько часов, нерабочие отсеиваются.
 *  Ссылки — raw GitHub; добавляются как обычная подписка и обновляются сами
 *  (Profile-Update-Interval у них — 1 ч). */
export type CatalogSub = {
  id: string;
  url: string;
  /** Чёрные списки — обычный интернет с блокировками; белые — мобильный режим «только разрешённое». */
  kind: "black" | "white";
  name: [ru: string, en: string];
  hint: [ru: string, en: string];
};

const RAW = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/";

export const XRAY_CATALOG: CatalogSub[] = [
  {
    id: "black-mobile",
    url: RAW + "BLACK_VLESS_RUS_mobile.txt",
    kind: "black",
    name: ["Чёрные списки · ТОП-150", "Blacklists · top 150"],
    hint: ["~150 лучших VLESS, VMess, Trojan и SS. С неё лучше начинать", "~150 best VLESS, VMess, Trojan and SS. A good place to start"],
  },
  {
    id: "black-vless",
    url: RAW + "BLACK_VLESS_RUS.txt",
    kind: "black",
    name: ["Чёрные списки · VLESS, полная", "Blacklists · VLESS, full"],
    hint: ["~450 серверов VLESS: больше выбор, дольше проверка", "~450 VLESS servers: more choice, longer tests"],
  },
  {
    id: "black-ss",
    url: RAW + "BLACK_SS%2BAll_RUS.txt",
    kind: "black",
    name: ["Чёрные списки · SS, VMess, Trojan", "Blacklists · SS, VMess, Trojan"],
    hint: ["~150 серверов других протоколов — когда VLESS режут", "~150 servers on other protocols — for when VLESS is cut"],
  },
  {
    id: "white-mobile",
    url: RAW + "Vless-Reality-White-Lists-Rus-Mobile.txt",
    kind: "white",
    name: ["Белые списки · мобильный интернет", "Whitelists · mobile internet"],
    hint: ["когда у мобильного оператора открыты только разрешённые сайты", "for when a mobile carrier only lets whitelisted sites through"],
  },
  {
    id: "white-sni",
    url: RAW + "WHITE-SNI-RU-all.txt",
    kind: "white",
    name: ["Белые списки · SNI-RU", "Whitelists · SNI-RU"],
    hint: ["серверы, которые маскируются под российские сайты", "servers disguised as Russian sites"],
  },
];
