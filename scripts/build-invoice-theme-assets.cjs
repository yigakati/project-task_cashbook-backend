// Original vector artwork for document themes. PNGs are shared by browser previews and PDFKit.
const { mkdirSync, writeFileSync } = require('node:fs');
const { resolve } = require('node:path');
const sharp = require('sharp');
const directory = resolve(__dirname, '../src/modules/invoicing/assets');
mkdirSync(directory, { recursive: true });
const frame = (color) =>
    `<rect x="18" y="18" width="758" height="1087" rx="18" fill="none" stroke="${color}" stroke-width="2"/>`;
const footer = (color) =>
    `<path d="M0 1107H794V1123H0Z" fill="${color}"/><path d="M100 1107l14 16h12l-14-16zm25 0l14 16h12l-14-16z" fill="white"/>`;
const themes = {
    outline: frame('#3267c8'),
    marble: `<defs><linearGradient id="m" x2="1" y2="1"><stop stop-color="#c8e4e5"/><stop offset=".5" stop-color="#e6f1ef"/><stop offset="1" stop-color="white"/></linearGradient></defs><rect width="794" height="1123" fill="url(#m)"/><path d="M-90 0Q460 190 50 350T300 860" fill="none" stroke="#8ebfca" stroke-width="110" opacity=".24"/><path d="M650-80Q30 140 610 420T440 1000" fill="none" stroke="#76a9b3" stroke-width="40" opacity=".2"/><path d="M100 190Q610 50 340 540T50 1000" fill="none" stroke="#e9d9ab" stroke-width="25" opacity=".45"/><path d="M-50 150Q520 360 390 600T770 1010" fill="none" stroke="white" stroke-width="80" opacity=".55"/>`,
    wave: `<path d="M0 0H794V142Q480 90 260 165T0 145Z" fill="#151b26"/><path d="M390 0Q570 95 794 65V99Q575 132 270 170Q590 100 390 0Z" fill="#969ba6"/><path d="M0 124Q220 226 794 108V146Q410 220 0 147Z" fill="#454b56"/>${footer('#151b26')}`,
    workshop: `<defs><linearGradient id="g" x2="1" y2="1"><stop stop-color="#737b82"/><stop offset="1" stop-color="#303a44"/></linearGradient></defs><rect width="794" height="164" fill="url(#g)"/>${Array.from({ length: 10 }, (_, i) => `<g transform="translate(${i * 93 - 40} -35) rotate(22)"><rect width="22" height="240" rx="7" fill="#9ca5ac"/>${Array.from({ length: 18 }, (_, j) => `<path d="M-3 ${j * 12}l30-5" stroke="#3d4853" stroke-width="4"/>`).join('')}</g>`).join('')}<rect width="794" height="164" fill="#111827" opacity=".65"/>${footer('#353a40')}`,
    panel: `<rect width="794" height="1123" fill="#243458"/><path d="M0 950L550 1123H0Z" fill="#aab5ce"/><path d="M350 990L794 1123H550Z" fill="#e6eaf0"/><rect x="32" y="161" width="730" height="795" rx="28" fill="white"/>`,
    ribbon: `<rect width="794" height="164" fill="#203263"/><path d="M365 0h38l90 164h-38z" fill="#d0d4df"/><path d="M406 0h18l90 164h-18z" fill="white"/><path d="M420 0h8l90 164h-8z" fill="#838caa"/>${footer('#203263')}`,
    watermark: frame('#e7ebf0'),
    estate: `<rect width="794" height="166" fill="#71969a"/><g stroke="#273f4d" stroke-width="3"><path d="M484 84l120-70 182 72-120 46z" fill="#3f5860"/><path d="M516 96v70h243V99l-98 33z" fill="#a2bbbd"/><path d="M543 116v49h53v-58zM671 132v33h53v-48z" fill="#567f8a"/><path d="M608 131v35h33v-34z" fill="#354d59"/></g><rect width="794" height="166" fill="#284650" opacity=".3"/>${footer('#51808a')}`,
    angle: `<path d="M0 0H365L0 910Z" fill="#0f9979"/><path d="M0 910L181 433L586 1123H0Z" fill="#eff3f4"/><path d="M0 0H365L280 205H0Z" fill="#13b891" opacity=".6"/>`,
    pastel: `<defs><linearGradient id="p"><stop stop-color="#a6d6ec"/><stop offset=".55" stop-color="#fbdfed"/><stop offset="1" stop-color="#f9c3de"/></linearGradient></defs><rect width="794" height="165" fill="url(#p)"/><path d="M160 0Q160 100 340 83T470 166H310Q370 139 238 132T100 0Z" fill="white" opacity=".3"/>${footer('#74b8da')}`,
    botanical: `<path d="M-20 0Q185 200 34 529T150 1123H0Z" fill="#d9ebba" opacity=".65"/><path d="M55 0Q-23 310 90 569T58 1123H0Q115 823 11 592T-10 0Z" fill="#f7eac4" opacity=".7"/><path d="M0 530Q173 830 65 1090L0 1123Z" fill="#d4eaf2" opacity=".65"/>`,
    mesh: `<g stroke="#e6eaf0" stroke-width="1.5" fill="none"><path d="M0 5l350 156L180 0L60 171L0 5l210 62L794 0M0 160L530 10L690 166L30 32M0 940l480 183L330 900l-90 223L0 940l794 64M0 1123l440-200L690 1123l104-180M450 923l344 146"/></g>`,
};
(async () => {
    for (const [name, content] of Object.entries(themes)) {
        const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="794" height="1123" viewBox="0 0 794 1123"><rect width="794" height="1123" fill="white"/>${name === 'workshop' ? `<defs><clipPath id="header"><rect width="794" height="164"/></clipPath></defs><g clip-path="url(#header)">${content}</g>${footer('#353a40')}` : content}</svg>`;
        writeFileSync(resolve(directory, `${name}.svg`), svg);
        await sharp(Buffer.from(svg))
            .png()
            .toFile(resolve(directory, `${name}.png`));
    }
})().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
