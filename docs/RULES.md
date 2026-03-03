# Web Analyser — Rules Reference

This document explains every detection rule that ships with Web Analyser, describes how the rule engine works, and proposes patterns for future rules.

---

## Table of Contents

1. [How Rules Work](#how-rules-work)
   - [Rule File Format](#rule-file-format)
   - [Evidence Types](#evidence-types)
   - [Confidence Model](#confidence-model)
2. [Current Rules](#current-rules)
   - [Backend (`backend.yaml`)](#backend-backendyaml)
   - [Frontend (`frontend.yaml`)](#frontend-frontendyaml)
   - [JavaScript (`javascript.yaml`)](#javascript-javascriptyaml)
   - [CSS (`css.yaml`)](#css-cssyaml)
   - [Cookies (`cookies.yaml`)](#cookies-cookiesyaml)
   - [Network (`network.yaml`)](#network-networkyaml)
   - [Favicon (`favicon.yaml`)](#favicon-faviconyaml)
   - [Forms (`forms.yaml`)](#forms-formsyaml)
   - [Subresource Integrity (`sri.yaml`)](#subresource-integrity-sriyaml)
   - [Assets (`assets.yaml`)](#assets-assetsyaml)
   - [Security (`security.yaml`)](#security-securityyaml)
   - [API Keys & Credentials (`api_keys.yaml`)](#api-keys--credentials-api_keysyaml)
3. [Possible Future Rules](#possible-future-rules)
   - [HTTP Protocol & Performance](#http-protocol--performance)
   - [WebSocket & Real-Time Technologies](#websocket--real-time-technologies)
   - [GraphQL & API Frameworks](#graphql--api-frameworks)
   - [Containerisation & Orchestration](#containerisation--orchestration)
   - [Feature Flags & Experimentation](#feature-flags--experimentation)
   - [CRM & Customer Platforms](#crm--customer-platforms)
   - [Localisation & Internationalisation (i18n)](#localisation--internationalisation-i18n)
   - [Progressive Web App (PWA) Indicators](#progressive-web-app-pwa-indicators)
   - [Accessibility & Testing Tools](#accessibility--testing-tools)
   - [Build Tool Fingerprints](#build-tool-fingerprints)
   - [Monitoring & Observability](#monitoring--observability)
   - [Headless Browser & Scraping Defences](#headless-browser--scraping-defences)

---

## How Rules Work

### Rule File Format

Rules are written in YAML and grouped by category into separate files under the `rules/` directory. Each rule follows this schema:

```yaml
- name: <Technology Name>           # Human-readable name shown in results
  category: <Category>              # Grouping label (e.g. "Web Server", "CMS")
  version_pattern: <regex>          # Optional: regex with one capture group for the version string
  version: <string>                 # Optional: static version when known exactly (e.g. SRI rules)
  evidence:
    - type: <evidence_type>         # How to detect this technology (see Evidence Types)
      name: <header/field name>     # Used by header, dns_record, hidden_field_name, cookie (exact name)
      pattern: <regex>              # Regex applied to header value, HTML content, URLs, etc.
      value: <string>               # Used by sri_hash, favicon_hash, hidden_field_name (exact value)
      confidence: <0.0 – 1.0>       # How certain this single signal makes us
```

Multiple evidence entries are combined additively (see [Confidence Model](#confidence-model)). All pattern matching is case-insensitive by default.

### Evidence Types

| Evidence Type | Source | What It Inspects |
|---|---|---|
| `header` | HTTP response headers | Matches `name` header value against `pattern` |
| `cookie` | HTTP `Set-Cookie` headers | Matches cookie name against `name` (exact) or `pattern` (regex) |
| `html_pattern` | Raw HTML body | Regex search across entire HTML source |
| `html_comment` | HTML `<!-- ... -->` blocks | Regex search inside comment text only |
| `meta_tag` | `<meta>` elements | Matches `name` and `content` attributes |
| `script_src` | `<script src="...">` attributes | Regex on the `src` URL |
| `js_global` | Inline and external JavaScript | Regex search for global variable/property names |
| `js_comment` | JavaScript block/line comments | Regex inside JS comment text |
| `script_content_pattern` | Full text of external JS files | Regex across downloaded script content |
| `inline_js_variable` | Inline `<script>` blocks | Regex for variable declarations/assignments |
| `css_link` | `<link rel="stylesheet">` `href` attributes | Regex on the stylesheet URL |
| `css_class` | `class="..."` attribute values | Regex across all class attribute strings |
| `dns_record` | DNS query results | Matches record type (`name`) value against `pattern` |
| `tls_issuer` | TLS certificate issuer fields | Matches issuer field (`name`) against `pattern` |
| `tls_subject` | TLS certificate subject fields | Matches subject field (`name`) against `pattern` |
| `certificate_issuer` | Parsed TLS issuer CN/O | Regex on the certificate issuer string |
| `certificate_cn` | Parsed TLS subject CN | Regex on the certificate common name |
| `favicon_hash` | MD5 hash of `/favicon.ico` | Exact match against `value` |
| `sri_hash` | `integrity="..."` attribute values | Exact match against `value` |
| `hidden_field_name` | `<input type="hidden" name="...">` | Matches input `name` attribute against `value` |
| `form_action_pattern` | `<form action="...">` attributes | Regex on the form `action` URL |
| `font_src_pattern` | `@font-face src:` and `<link>` for fonts | Regex on the URL |
| `image_src_pattern` | `<img src="...">` and CSS `background` URLs | Regex on the URL |
| `video_embed_pattern` | `<iframe>` and `<video>` `src` attributes | Regex on the embed URL |
| `api_key_pattern` | All text content (HTML, JS, inline) | Regex for credential/key patterns |
| `connection_string` | All text content | Regex for database/service connection strings |
| `private_key` | All text content | Regex for PEM-encoded private key blocks |

### Confidence Model

Each evidence item carries a `confidence` score between `0.0` (no certainty) and `1.0` (absolute certainty). When a technology has multiple evidence entries, the total confidence is computed as:

```
C_total = min(1.0, Σ confidence_i)
```

Only evidence items that actually match are included in the sum. This means:

- A **single strong signal** (e.g. a unique header, confidence 0.9) produces a high-confidence result on its own.
- **Multiple weak signals** (e.g. common CSS class names, each 0.3–0.4) can combine to cross a meaningful threshold, reducing false positives.
- The **cap at 1.0** prevents overflow; no detection can exceed 100 % certainty.

Results are only emitted when at least one evidence item matches.

---

## Current Rules

### Backend (`backend.yaml`)

Detects web servers, application servers, frameworks, runtimes, CDNs, and hosting providers via HTTP response headers and cookies.

| Technology | Category | Detection Method | Key Signal |
|---|---|---|---|
| Nginx | Web Server | `Server` header | `nginx` |
| Apache HTTP Server | Web Server | `Server` header | `apache` |
| Microsoft-IIS | Web Server | `Server` header | `Microsoft-IIS` |
| LiteSpeed | Web Server | `Server` header | `LiteSpeed` |
| Google Web Server | Web Server | `Server` header | `gws` |
| OpenResty | Web Server | `Server` header | `openresty` |
| Caddy | Web Server | `Server` header | `Caddy` |
| Jetty | Web Server | `Server` header | `Jetty` |
| Apache Tomcat | Web Server | `Server` or `X-Powered-By` | `Apache-Coyote` / `Servlet` |
| Varnish | Web Accelerator | `Server` header | `Varnish` |
| Express | Web Framework | `X-Powered-By` | `express` |
| PHP | Programming Language | `X-Powered-By` + cookie | `php` / `PHPSESSID` |
| Django | Web Framework | Cookie | `csrftoken` |
| Flask | Web Framework | `Server` header + cookie | `Werkzeug` / `session` |
| FastAPI | Web Framework | `Server` header | `uvicorn` |
| Ruby on Rails | Web Framework | Cookie | `_session_id` |
| ASP.NET | Web Framework | `X-Powered-By` + `X-AspNet-Version` | `ASP.NET` |
| ASP.NET Core | Web Framework | `X-Powered-By` | `ASP.NET Core` |
| Spring Framework | Web Framework | `X-Application-Context` + cookie | any value / `JSESSIONID` |
| Laravel | Web Framework | Cookie + `X-Powered-By` | `laravel_session` / `Laravel` |
| Symfony | Web Framework | Cookie + `X-Powered-By` | `symfony` / `Symfony` |
| Koa | Web Framework | `X-Powered-By` | `koa` |
| NestJS | Web Framework | `X-Powered-By` | `NestJS` |
| Node.js | Runtime | `X-Powered-By` | `Node` |
| Go | Programming Language | `X-Powered-By` | `Go` |
| Gunicorn | Application Server | `Server` header | `gunicorn` |
| uWSGI | Application Server | `Server` header | `uwsgi` |
| Puma | Application Server | `Server` header | `puma` |
| Passenger | Application Server | `Server` or `X-Powered-By` | `Phusion Passenger` |
| Unicorn | Application Server | `Server` header | `Unicorn` |
| Fastly | CDN | `Server` header | `Fastly` |
| Amazon CloudFront | CDN | `X-Amz-Cf-Id` + `Via` | any value / `CloudFront` |
| Akamai | CDN | `X-Akamai-Transformed` + `Server` | any value / `AkamaiGHost` |
| Netlify | Hosting | `Server` + `X-NF-Request-ID` | `Netlify` |
| Vercel | Hosting | `Server` + `X-Vercel-ID` | `Vercel` |
| HAProxy | Load Balancer | `Server` header | `HAProxy` |
| Traefik | Load Balancer | `Server` header | `traefik` |

**How it works:** The HTTP `Server` header is the most common signal — many web servers self-identify there. `X-Powered-By` is set by many frameworks (Express, PHP, ASP.NET). Session cookie names are highly framework-specific (e.g. `csrftoken` is generated only by Django's CSRF middleware). The CDN/hosting signals look for vendor-specific request-ID headers that are injected by the platform.

---

### Frontend (`frontend.yaml`)

Detects CMS platforms, frontend frameworks, and static site generators by analysing HTML source.

| Technology | Category | Key Pattern |
|---|---|---|
| WordPress | CMS | `<meta name="generator" content="WordPress ...">`, HTML comments with `WordPress\|Theme Name:` |
| Drupal | CMS | Generator meta tag, `drupalSettings` JS object in HTML |
| Joomla | CMS | Generator meta tag, `/media/jui/js/` asset path |
| Wix | CMS | `wix.com` or `wixstatic.com` in HTML |
| Webflow | CMS | `webflow.com` or `webflow.io` in HTML |
| Ghost | CMS | Generator meta tag `ghost` |
| Squarespace | CMS | Generator meta tag `squarespace` |
| Contentful | Headless CMS | `contentful` in HTML |
| Strapi | Headless CMS | `strapi` in HTML |
| Shopify | Ecommerce | Generator meta tag `shopify` |
| Magento | Ecommerce | `Mage.Cookies\|mage/cookies` JS globals in HTML |
| WooCommerce | Ecommerce | (via forms rule — see below) |
| PrestaShop | Ecommerce | `prestashop` in HTML |
| BigCommerce | Ecommerce | `bigcommerce` in HTML |
| OpenCart | Ecommerce | `route=\|catalog/view/` URL patterns |
| React | Frontend Framework | `<div id="react-root">` or `<div id="root">`, `@license React` JS comment |
| Vue.js | Frontend Framework | `id="app"` (weak), `data-v-app` attribute (strong), Vue version comment |
| Angular | Frontend Framework | `ng-version="..."` attribute on any element |
| Svelte | Frontend Framework | `data-svelte` attribute |
| Next.js | Frontend Framework | `<div id="__next">` |
| Nuxt.js | Frontend Framework | `<div id="__nuxt">`, `data-n-head` attribute |
| Remix | Frontend Framework | `remix` in HTML (weak) |
| SolidJS | Frontend Framework | `data-solid` attribute |
| Preact | Frontend Framework | (also via JS global in javascript.yaml) |
| Gatsby | Static Site Generator | `___gatsby` in HTML, `<div id="___gatsby">` |
| Jekyll | Static Site Generator | `<!-- generated by jekyll -->` comment (confidence 1.0) |
| Hugo | Static Site Generator | Generator meta tag `hugo` |
| Astro | Static Site Generator | `astro-` in HTML |
| Eleventy | Static Site Generator | Generator meta tag `eleventy` |
| Hexo | Static Site Generator | Generator meta tag `hexo` |
| Pelican | Static Site Generator | Generator meta tag `pelican` |

**How it works:** The `<meta name="generator">` pattern is the most reliable signal — many CMSs and static site generators insert it by default. Framework-specific attributes (e.g. `data-v-app` for Vue, `ng-version` for Angular) are injected at build time and are hard to remove accidentally. Root element IDs (`__next`, `__nuxt`, `___gatsby`) are framework conventions. JS comments containing license information or framework branding are embedded in minified bundles.

---

### JavaScript (`javascript.yaml`)

Detects JavaScript libraries, analytics tools, payment SDKs, and identity providers via script URLs, JS globals, and script content.

| Technology | Category | Key Signal |
|---|---|---|
| React | Frontend Framework | `react.js` script src, `__REACT_DEVTOOLS_GLOBAL_HOOK__` or `React` global |
| Angular | Frontend Framework | `angular.js` script src, `angular` global |
| Vue.js | Frontend Framework | `vue.js` script src, `Vue` global |
| jQuery | JavaScript Library | `jquery*.js` src, `jQuery` or `$` global |
| Lodash | JavaScript Library | `lodash*.js` src, `_.VERSION` / `_.map` etc. globals |
| Moment.js | JavaScript Library | `moment*.js` src, `moment` global |
| Alpine.js | JavaScript Library | `alpine.js` src, `Alpine` global |
| Preact | Frontend Framework | `preact.js` src, `preact` or `Preact` global |
| D3.js | JavaScript Library | `d3.js` src, `d3` global |
| Three.js | JavaScript Library | `three.js` src, `THREE` global |
| GSAP | JavaScript Library | `gsap.js` src, `gsap` global |
| Stripe.js | Payments | `js.stripe.com` src, `Stripe` global |
| PayPal Checkout | Payments | `js.paypal.com` src, `paypal` global |
| Square | Payments | `square.github.io` src, `SqPaymentForm` global |
| Braintree | Payments | `braintree` in src, `braintree` global |
| Auth0 | Identity | `cdn.auth0.com` src, `Auth0` global |
| Okta | Identity | `okta.com\|oktacdn` src, `OktaAuth` global |
| Firebase Auth | Identity | `firebase` src, `firebase\|FirebaseAuth` global |
| Google Tag Manager | Analytics | `gtm.js` src, `dataLayer` global |
| Google Analytics | Analytics | `analytics.js\|gtag/js` src, `gtag` or `ga` global, inline script patterns |
| Segment | Analytics | `cdn.segment.com` src, `analytics` global |
| Mixpanel | Analytics | `mixpanel.com` src, `mixpanel` global, `mixpanel.init` in script content |
| Hotjar | Analytics | `static.hotjar.com` src, `hj` global, `hjid\|hjsv` in script content |
| Matomo | Analytics | `matomo\|piwik` src, `_paq` global |

**Version detection:** Rules in this file include `version_pattern` fields (e.g. `react[@/-]v?(\d+\.\d+\.\d+[-.\w]*)`) which are matched against the script `src` URL to extract version numbers automatically.

**How it works:** Script `src` URL matching identifies libraries loaded from CDNs or self-hosted with canonical filenames. JS globals are the most reliable signal — each library registers a unique global object. Script content patterns scan the text of downloaded JS files for initialisation calls (e.g. `mixpanel.init(...)`) or library-specific strings not present in other libraries.

---

### CSS (`css.yaml`)

Detects CSS frameworks and icon/animation libraries via stylesheet link URLs and HTML class names.

| Technology | Category | CSS Link Pattern | HTML Class Signal |
|---|---|---|---|
| Bootstrap | CSS Framework | `bootstrap(\.min)?\.css` | `col-`, `container`, `row`, `card`, `btn` |
| Tailwind CSS | CSS Framework | `tailwind(\.min)?\.css` | `flex`, `grid`, `p-`, `m-`, `text-` |
| Bulma | CSS Framework | `bulma(\.min)?\.css` | `navbar`, `hero`, `section`, `columns` |
| Foundation | CSS Framework | `foundation(\.min)?\.css` | `grid-x`, `cell`, `button`, `callout` |
| Materialize | CSS Framework | `materialize(\.min)?\.css` | `container`, `row`, `col`, `card`, `btn` |
| Semantic UI | CSS Framework | `semantic(\.min)?\.css` | `ui grid`, `ui button`, `ui card` |
| UIKit | CSS Framework | `uikit(\.min)?\.css` | `uk-` prefix classes |
| Pure.css | CSS Framework | `pure(\.min)?\.css` | `pure-` prefix classes |
| Spectre.css | CSS Framework | `spectre(\.min)?\.css` | — |
| Milligram | CSS Framework | `milligram(\.min)?\.css` | — |
| Tachyons | CSS Framework | `tachyons(\.min)?\.css` | — |
| Skeleton | CSS Framework | `skeleton(\.min)?\.css` | — |
| Material Design Lite | CSS Framework | `material(\.min)?\.css` | `mdl-` prefix classes |
| Ant Design | UI Library | `antd(\.min)?\.css` | `ant-` prefix classes |
| Chakra UI | UI Library | — | `chakra-` prefix classes |
| Material-UI | UI Library | — | `MuiBox`, `MuiButton`, `MuiTypography` |
| DaisyUI | UI Library | `daisyui` in href | `data-theme=`, generic utility class names |
| Font Awesome | Icon Library | `fontawesome` or `font-awesome` CSS | `fa-` prefix classes |
| Bootstrap Icons | Icon Library | `bootstrap-icons(\.min)?\.css` | `bi-` prefix classes |
| Feather Icons | Icon Library | — | `feather` in HTML |
| Animate.css | Animation Library | `animate(\.min)?\.css` | `animate__` prefix classes |

**How it works:** The canonical stylesheet filename (`bootstrap.min.css`, `tailwind.css`, etc.) is the highest-confidence signal — it is a direct reference to the library file. CSS class name patterns are lower-confidence because class names like `container`, `row`, or `btn` are common in hand-written CSS. They work best as corroborating evidence alongside a stylesheet link.

---

### Cookies (`cookies.yaml`)

Detects technologies by matching cookie names (exact string or regex pattern) set in HTTP `Set-Cookie` headers.

| Technology | Category | Cookie Signal |
|---|---|---|
| WordPress | CMS | Name starts with `wp-settings-` |
| Cloudflare | CDN | `__cfduid`, `cf_clearance` |
| Laravel | Web Framework | `XSRF-TOKEN`, `laravel_session` |
| Shopify | Ecommerce | `_shopify_y`, `_shopify_s`, `secure_customer_sig` |
| Drupal | CMS | Name matches `SESS[a-z0-9]+` |
| Joomla | CMS | Name matches `[a-z0-9]+sessionid` |
| Magento | Ecommerce | `frontend`, `X-Magento-Vary` |
| PrestaShop | Ecommerce | `PrestaShop-` prefix |
| Wix | CMS | Name matches `wix\|svSession` |
| Squarespace | CMS | `SS_MID` |
| HubSpot | Marketing | `hubspotutk`, `__hstc` |
| Marketo | Marketing | `_mkto_trk` |
| Pardot | Marketing | `visitor_id`, name matches `pardot` |
| Intercom | Customer Support | `intercom-id`, `intercom-session` |
| Zendesk | Customer Support | Name matches `_zendesk_` |
| Hotjar | Analytics | `_hjid`, `_hjSessionUser_` |
| Mixpanel | Analytics | `mp_` prefix |
| Optimizely | A/B Testing | Name matches `optimizely` |
| VWO | A/B Testing | Name matches `_vwo_` |
| Stripe | Payments | Name matches `stripe` (weak) |
| PayPal | Payments | Name matches `paypal` (weak) |
| Sentry | Error Tracking | Name matches `sentry` |

**How it works:** Cookies are often set with vendor-specific naming conventions that are documented or observable in production. Unique session cookie names (e.g. `csrftoken` for Django, `JSESSIONID` for Java EE) are set by framework middleware automatically. Marketing and analytics platforms use consistent first-party cookie names across all customer deployments.

---

### Network (`network.yaml`)

Detects CDN providers, cloud platforms, certificate authorities, and email infrastructure via DNS records and TLS certificate inspection.

| Technology | Category | Signal |
|---|---|---|
| Cloudflare | CDN | TLS issuer `organizationName` matches `cloudflare`, DNS CNAME matches `cloudflare.net` |
| Amazon Web Services | IaaS | DNS CNAME matches `amazonaws.com` |
| Microsoft Azure | IaaS | DNS CNAME matches `azurewebsites.net\|cloudapp.net` |
| Akamai | CDN | DNS CNAME matches `akamaihd.net\|edgekey.net\|edgesuite.net` |
| Fastly | CDN | DNS CNAME matches `fastly.net` |
| Amazon CloudFront | CDN | DNS CNAME matches `cloudfront.net` |
| Netlify | Hosting | DNS CNAME matches `netlify.app` |
| Vercel | Hosting | DNS CNAME matches `vercel.app` |
| DigiCert | Certificate Authority | TLS issuer `organizationName` matches `DigiCert` |
| Sectigo | Certificate Authority | TLS issuer `organizationName` matches `Sectigo\|COMODO` |
| Google Search Console | SEO | DNS TXT record contains `google-site-verification` |
| SPF Record Present | Email | DNS TXT record contains `v=spf1` |
| DMARC Policy | Email Security | DNS TXT record contains `v=DMARC1` |
| DKIM Signing | Email Security | DNS TXT record contains `v=DKIM1` |
| MTA-STS | Email Security | DNS TXT record contains `v=STSv1` |
| Mailgun | Email | DNS CNAME matches `mailgun.org` |
| SendGrid | Email | DNS CNAME matches `sendgrid` |
| Mailchimp | Email | DNS CNAME matches `mailchimp` |

**How it works:** DNS CNAME records pointing to a CDN or hosting provider's domain are definitive evidence of that service being used. TLS certificate issuer fields identify the certificate authority that issued the site's SSL certificate. DNS TXT records contain structured strings for email security protocols (SPF, DMARC, DKIM) that follow a well-defined `v=<protocol>` format.

---

### Favicon (`favicon.yaml`)

Detects CMS platforms by computing the MD5 hash of the site's `/favicon.ico` and comparing it to known values.

| Technology | Category | MD5 Hash |
|---|---|---|
| WordPress | CMS | `5d5e3efa5f0c4f64a1c89c3e9c7b4a8f` |
| Drupal | CMS | `7f4e3b2a1c9d8e6f5a4b3c2d1e0f9a8b` |
| Joomla | CMS | `3c9e4f5a6b7d8e9f0a1b2c3d4e5f6a7b` |
| Shopify | Ecommerce | `a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6` |
| Magento | Ecommerce | `e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6` |

**How it works:** Default platform favicons are rarely customised in default or low-effort deployments. The MD5 hash of the default CMS favicon is stable across installations of the same version, making it a reliable fingerprint when the default icon has not been replaced.

---

### Forms (`forms.yaml`)

Detects backend frameworks and CMS platforms by inspecting hidden form fields and form action URL patterns.

| Technology | Category | Signal |
|---|---|---|
| Django | Backend Framework | Hidden field `csrfmiddlewaretoken` |
| ASP.NET | Backend Framework | Hidden fields `__VIEWSTATE`, `__EVENTVALIDATION` |
| Ruby on Rails | Backend Framework | Hidden field `authenticity_token` |
| Laravel | Backend Framework | Hidden field `_token` |
| Symfony | Backend Framework | (cookie detection in backend.yaml) |
| Magento | Ecommerce | Hidden field `form_key` |
| WooCommerce | Ecommerce | Hidden field `_wp_http_referer`, form action contains `?wc-ajax=` |
| PrestaShop | Ecommerce | Hidden field `submitMessage` |
| TYPO3 | CMS | Hidden field `__referrer[@extension]` |
| Craft CMS | CMS | Hidden field `CRAFT_CSRF_TOKEN` |
| SharePoint | CMS | Form action matches `/_layouts/\d+/`, hidden field `__REQUESTDIGEST` |

**How it works:** Server-side frameworks inject CSRF (Cross-Site Request Forgery) protection tokens into every HTML form as hidden fields. The name of that token is framework-specific and does not change between deployments. These are high-confidence signals because the token names are hardcoded in the framework's form-rendering middleware.

---

### Subresource Integrity (`sri.yaml`)

Identifies the exact version of a library by matching the `integrity` attribute hash on `<script>` and `<link>` tags.

| Technology | Category | Version | Hash Algorithm |
|---|---|---|---|
| Bootstrap | Frontend Framework | 5.3.0 | SHA-384 |
| jQuery | JavaScript Library | 3.7.1 | SHA-256 |
| Font Awesome | Icon Library | 6.4.0 | SHA-512 |
| React | JavaScript Library | 18.2.0 | SHA-512 |
| Vue.js | JavaScript Framework | 3.3.4 | SHA-512 |
| Lodash | JavaScript Utility | 4.17.21 | SHA-512 |
| Chart.js | Visualization | 4.3.0 | SHA-512 |
| Axios | HTTP Client | 1.4.0 | SHA-512 |
| Moment.js | Date/Time Library | 2.29.4 | SHA-512 |

**How it works:** The SRI `integrity` attribute contains a cryptographic hash of the exact file content. Because the hash changes with every byte of the file, matching a known hash proves both the identity of the library **and** its exact version number. This is the highest-confidence detection method (all entries have confidence 0.95). It is limited to libraries loaded from public CDNs with well-known SRI hashes.

---

### Assets (`assets.yaml`)

Detects external services by inspecting asset URLs found in `<script src>`, `<link href>`, `<img src>`, `<iframe src>`, CSS `@font-face`, and background image declarations.

| Technology | Category | URL Pattern |
|---|---|---|
| Google Fonts | Font Service | `fonts.googleapis.com`, `fonts.gstatic.com` |
| Adobe Fonts | Font Service | `use.typekit.net`, `typekit.net` |
| Font Squirrel | Font Service | `fontsquirrel.com` |
| Fonts.com | Font Service | `fast.fonts.net` |
| Material Icons | Icon Library | `fonts.googleapis.com/icon`, `material-icons` class |
| Ionicons | Icon Library | `code.ionicframework.com/ionicons` |
| Line Awesome | Icon Library | `line-awesome` in URL |
| Remix Icon | Icon Library | `remixicon` in URL |
| Cloudinary | Image CDN | `res.cloudinary.com` |
| Imgix | Image CDN | `imgix.net` |
| Fastly Image Optimizer | Image CDN | `fastly.net` in URL with query params |
| Cloudflare Images | Image CDN | `imagedelivery.net` |
| ImageKit | Image CDN | `imagekit.io` |
| Uploadcare | Image CDN | `ucarecdn.com` |
| Vimeo | Video Service | `player.vimeo.com` |
| YouTube | Video Service | `youtube.com/embed\|youtube-nocookie.com` |
| Wistia | Video Service | `fast.wistia.com\|fast.wistia.net` |
| JW Player | Video Player | `jwplayer\|jwpsrv.com` |
| jsDelivr | JavaScript CDN | `cdn.jsdelivr.net` |
| cdnjs | JavaScript CDN | `cdnjs.cloudflare.com` |
| unpkg | JavaScript CDN | `unpkg.com` |
| Google Hosted Libraries | JavaScript CDN | `ajax.googleapis.com` |
| GitHub Pages | Hosting | `github.io` CNAME, `GitHub.com` Server header |
| AWS S3 | Hosting | `AmazonS3` Server header |
| Firebase Hosting | Hosting | `Firebase` Server header |
| Lottie | Animation | `lottie` in script src |
| Three.js CDN | 3D Graphics | `three` in script src |
| Particle.js | Animation | `particles` in script src |

**How it works:** Third-party service URLs are highly distinctive. A `src` URL containing `res.cloudinary.com` can only originate from Cloudinary, for example. Font service detection targets both the CSS `<link>` that loads the font stylesheet and the `@font-face src:` URLs that reference font files, ensuring detection works whether the CSS is inline or external.

---

### Security (`security.yaml`)

Detects Web Application Firewalls (WAFs), DDoS protection, bot mitigation, rate limiting, security headers, authentication systems, and security plugins.

#### Web Application Firewalls

| Technology | Detection | Signal |
|---|---|---|
| Cloudflare WAF | Headers | `cf-ray` (0.95), `cf-cache-status` (0.90) |
| AWS WAF | Headers | `x-amzn-requestid` (0.90), `x-amz-cf-id` (0.85) |
| Akamai WAF | Header | `x-akamai-transformed` (0.95) |
| Imperva Incapsula | Header + cookies | `x-iinfo`, `incap_ses`, `visid_incap` |
| Sucuri WAF | Headers | `x-sucuri-id` (0.95), `x-sucuri-cache` (0.90) |
| ModSecurity | Server header | `server` value contains `ModSecurity` |
| F5 BIG-IP ASM | Cookie + header | Cookie matching `TS[a-f0-9]{6}`, `x-wa-info` |

#### DDoS & Bot Protection

| Technology | Signal |
|---|---|
| Cloudflare DDoS Protection | `cf-ray` header |
| Fastly Shield | `x-served-by` header matching `cache-.*-fastly` |
| reCAPTCHA | Script from `google.com/recaptcha` or `gstatic.com/recaptcha` |
| hCaptcha | Script from `hcaptcha.com` |
| Turnstile (Cloudflare) | Script from `challenges.cloudflare.com` |

#### Security Headers

| Rule | Header | Pattern |
|---|---|---|
| Secure HSTS Configuration | `strict-transport-security` | `max-age=31536000.*includeSubDomains` |
| Content Security Policy Configured | `content-security-policy` | Any value present |
| X-Frame-Options Protection | `x-frame-options` | `DENY\|SAMEORIGIN` |
| Referrer Policy Configured | `referrer-policy` | `no-referrer\|strict-origin*` |
| CORS Enabled | `access-control-allow-origin` | Any value present |
| Rate Limiting Active | `x-ratelimit-limit` / `ratelimit-limit` | Any value present |

#### Authentication

| Rule | Signal |
|---|---|
| OAuth 2.0 | `oauth` in HTML or script src |
| JWT Authentication | Cookie named `jwt` or `token` |
| SAML Authentication | `saml` or `saml2` in HTML |

#### Security Plugins

| Plugin | Signal |
|---|---|
| Wordfence | Cookie `wfvt_`, `wordfence` in HTML |
| iThemes Security | Cookie `itsec-hb` |
| All In One WP Security | `aiowps` in HTML |

**How it works:** WAF vendors inject proprietary HTTP headers into every response passing through their platform. These headers (`cf-ray`, `x-sucuri-id`, `x-iinfo`) are unique to each vendor and not added by origin servers, making them reliable fingerprints. Security headers are detected by looking for the header name and, where applicable, verifying the value follows the recommended security pattern (e.g. HSTS must include `includeSubDomains` to be considered "secure").

---

### API Keys & Credentials (`api_keys.yaml`)

> **Warning: Use responsibly.** These rules detect secrets inadvertently exposed in HTML, JavaScript, or other web resources. Only scan targets you own or have explicit written permission to scan.

Detects exposed credentials by scanning all text content with regular expressions targeting known credential formats.

#### Cloud Credentials

| Rule | Pattern | Confidence |
|---|---|---|
| AWS Access Key | `AKIA[0-9A-Z]{16}` | 0.95 |
| AWS Secret Key | `(?i)aws_secret_access_key.*?[a-zA-Z0-9/+=]{40}` | 0.90 |
| Google API Key | `AIza[0-9A-Za-z\-_]{35}` | 0.95 |
| Google OAuth Token | `\d{12}-[a-z0-9]{32}.apps.googleusercontent.com` | 0.90 |

#### Payment Credentials

| Rule | Pattern | Confidence |
|---|---|---|
| Stripe API Key | `sk_(live\|test)_[0-9a-zA-Z]{20,}` | 0.95 |
| Stripe Publishable Key | `pk_(live\|test)_[0-9a-zA-Z]{20,}` | 0.95 |

#### Source Control Credentials

| Rule | Pattern | Confidence |
|---|---|---|
| GitHub Personal Access Token | `ghp_[0-9a-zA-Z]{36}` | 0.95 |
| GitHub OAuth Token | `gho_[0-9a-zA-Z]{36}` | 0.95 |

#### Cryptographic Keys

| Rule | Pattern |
|---|---|
| RSA Private Key | `-----BEGIN RSA PRIVATE KEY-----` … `-----END RSA PRIVATE KEY-----` |
| DSA Private Key | `-----BEGIN DSA PRIVATE KEY-----` … `-----END DSA PRIVATE KEY-----` |
| EC Private Key | `-----BEGIN EC PRIVATE KEY-----` … `-----END EC PRIVATE KEY-----` |
| OpenSSH Private Key | `-----BEGIN OPENSSH PRIVATE KEY-----` … `-----END OPENSSH PRIVATE KEY-----` |

#### Database Connection Strings

| Rule | Pattern |
|---|---|
| MySQL | `mysql://user:pass@host/db` |
| PostgreSQL | `postgres(ql)://user:pass@host/db` |
| MongoDB | `mongodb(+srv)://user:pass@host/db` |
| Redis | `redis://user:pass@host` |

#### Communication & SaaS Credentials

| Rule | Pattern | Confidence |
|---|---|---|
| JWT Token | `eyJ...eyJ...signature` (base64url) | 0.80 |
| Slack Bot Token | `xoxb-\d+-\d+-[a-zA-Z0-9_-]+` | 0.95 |
| Slack App Token | `xapp-1-[a-zA-Z0-9_-]+` | 0.95 |
| SendGrid API Key | `SG.[22chars].[43chars]` | 0.95 |
| MailChimp API Key | `[32hex]-us\d{1,2}` | 0.80 |
| Twilio API Key | `SK[a-z0-9]{32}` | 0.70 |
| PagerDuty Token | `[20chars]+[20chars]` | 0.70 |

#### Generic Patterns

| Rule | Pattern | Confidence |
|---|---|---|
| Generic API Key | `(api_key\|apikey\|api_secret)[=:] <20+ chars>` | 0.60 |
| Authorization Header | `Authorization: (Bearer\|Token\|Basic) <value>` | 0.70 |
| Config File Password | `(password\|passwd\|pwd)[=:] <value>` | 0.50 |
| Database Password | `db_password[=:] <value>` | 0.60 |

**How it works:** All text content fetched from the target (HTML, inline JS, external JS files) is searched with these patterns. Vendor-specific credential formats (AWS keys starting with `AKIA`, Stripe keys with `sk_live_`) are highly precise with low false-positive rates. Generic patterns (`password=`) have lower confidence because they frequently appear in variable names or examples that are not live credentials.

---

## Possible Future Rules

This section describes additional detection rules that could be implemented, with the evidence patterns required for each.

### HTTP Protocol & Performance

#### HTTP/2 and HTTP/3 Support

Detect whether a site uses HTTP/2 or HTTP/3 (QUIC), which indicates modern server configuration.

```yaml
- name: HTTP/2 Enabled
  category: Protocol
  evidence:
    - type: http_version
      value: "2"
      confidence: 0.95

- name: HTTP/3 / QUIC Enabled
  category: Protocol
  evidence:
    - type: header
      name: alt-svc
      pattern: 'h3(-\d+)?='
      confidence: 0.90
```

**Pattern explanation:** `http_version` would be a new evidence type exposing the negotiated protocol version. The `alt-svc: h3=":443"` header advertises HTTP/3 availability; it is set by Cloudflare, Nginx (with QUIC patches), and LiteSpeed.

#### Server-Timing API

Detect sites exposing internal timing data via the `Server-Timing` header.

```yaml
- name: Server-Timing Exposed
  category: Performance
  evidence:
    - type: header
      name: server-timing
      pattern: '.'
      confidence: 0.70
```

**Pattern explanation:** Any non-empty `Server-Timing` header indicates the backend is using this API. Individual entries may reveal internal service names (e.g. `db;dur=23.4`), enabling further fingerprinting.

---

### WebSocket & Real-Time Technologies

#### Socket.io

```yaml
- name: Socket.io
  category: Real-Time
  evidence:
    - type: script_src
      pattern: 'socket\.io(\.min)?\.js'
      confidence: 0.90
    - type: js_global
      pattern: 'io\('
      confidence: 0.70
    - type: html_pattern
      pattern: '/socket\.io/'
      confidence: 0.80
```

**Pattern explanation:** Socket.io serves its client library from the same server at `/socket.io/socket.io.js`. The `io()` constructor call in inline scripts is a strong secondary signal.

#### Pusher

```yaml
- name: Pusher
  category: Real-Time
  evidence:
    - type: script_src
      pattern: 'js\.pusher\.com'
      confidence: 0.95
    - type: js_global
      pattern: 'Pusher'
      confidence: 0.90
```

#### Ably

```yaml
- name: Ably
  category: Real-Time
  evidence:
    - type: script_src
      pattern: 'cdn\.ably\.io|ably\.com'
      confidence: 0.90
    - type: js_global
      pattern: 'Ably|Realtime'
      confidence: 0.75
```

---

### GraphQL & API Frameworks

#### GraphQL Endpoint

```yaml
- name: GraphQL API
  category: API
  evidence:
    - type: html_pattern
      pattern: '/__graphql|/graphql'
      confidence: 0.60
    - type: script_content_pattern
      pattern: 'ApolloClient|gql`|graphql\('
      confidence: 0.80
```

**Pattern explanation:** GraphQL endpoints are conventionally served at `/graphql`. Client-side Apollo usage leaves `ApolloClient` instantiation and `gql` tagged template literal calls in the JS bundle.

#### Apollo Server

```yaml
- name: Apollo Server
  category: GraphQL
  evidence:
    - type: header
      name: x-apollo-operation-name
      confidence: 0.90
    - type: script_content_pattern
      pattern: 'Apollo Server|ApolloServer'
      confidence: 0.75
```

#### tRPC

```yaml
- name: tRPC
  category: API Framework
  evidence:
    - type: script_content_pattern
      pattern: 'createTRPCClient|createTRPCNext|trpc\.'
      confidence: 0.85
    - type: html_pattern
      pattern: '/api/trpc/'
      confidence: 0.80
```

**Pattern explanation:** tRPC uses a conventional `/api/trpc/` path prefix. The `createTRPCClient` factory and `trpc.` query chains are found in client-side bundles of Next.js/React apps using tRPC.

---

### Containerisation & Orchestration

#### Kubernetes Ingress

```yaml
- name: Kubernetes Ingress (NGINX)
  category: Infrastructure
  evidence:
    - type: header
      name: x-forwarded-for
      pattern: '.'
      confidence: 0.30
    - type: header
      name: x-real-ip
      pattern: '.'
      confidence: 0.35
    - type: header
      name: server
      pattern: 'nginx'
      confidence: 0.40
```

**Pattern explanation:** The combination of `X-Forwarded-For` and `X-Real-IP` headers, both set by the NGINX Ingress controller, together with an NGINX `Server` header, is a reasonable weak signal for Kubernetes-managed NGINX ingress.

#### Cloudflare Tunnel

```yaml
- name: Cloudflare Tunnel
  category: Infrastructure
  evidence:
    - type: header
      name: cf-ray
      confidence: 0.60
    - type: header
      name: cf-tunnel
      pattern: '.'
      confidence: 0.95
```

---

### Feature Flags & Experimentation

#### LaunchDarkly

```yaml
- name: LaunchDarkly
  category: Feature Flags
  evidence:
    - type: script_src
      pattern: 'launchdarkly\.com|ld-relay'
      confidence: 0.90
    - type: js_global
      pattern: 'LDClient|LDOptions'
      confidence: 0.85
```

#### Split.io

```yaml
- name: Split.io
  category: Feature Flags
  evidence:
    - type: script_src
      pattern: 'cdn\.split\.io'
      confidence: 0.90
    - type: js_global
      pattern: 'SplitFactory'
      confidence: 0.90
```

#### Unleash

```yaml
- name: Unleash
  category: Feature Flags
  evidence:
    - type: script_src
      pattern: 'unleash'
      confidence: 0.70
    - type: js_global
      pattern: 'unleash|UnleashClient'
      confidence: 0.85
```

**Pattern explanation:** Feature flag SDKs expose vendor-specific factory constructors (`LDClient`, `SplitFactory`, `UnleashClient`) as globals. CDN script URLs are the highest-confidence signal.

---

### CRM & Customer Platforms

#### Salesforce

```yaml
- name: Salesforce
  category: CRM
  evidence:
    - type: script_src
      pattern: 'salesforce\.com|force\.com|visualforce\.com'
      confidence: 0.90
    - type: html_pattern
      pattern: 'Visualforce|LightningOut|sforce'
      confidence: 0.80
    - type: cookie
      name: sid
      confidence: 0.40
```

#### HubSpot Forms

```yaml
- name: HubSpot Forms
  category: Marketing
  evidence:
    - type: script_src
      pattern: 'js\.hsforms\.net|js\.hs-scripts\.com'
      confidence: 0.95
    - type: js_global
      pattern: 'hbspt\.forms'
      confidence: 0.95
```

**Pattern explanation:** `hbspt.forms.create(...)` is the standard HubSpot embedded form initialisation call. The `js.hsforms.net` CDN is only used by HubSpot.

#### Freshdesk / Freshchat

```yaml
- name: Freshchat
  category: Customer Support
  evidence:
    - type: script_src
      pattern: 'wchat\.freshchat\.com'
      confidence: 0.95
    - type: js_global
      pattern: 'fcWidget'
      confidence: 0.90
```

---

### Localisation & Internationalisation (i18n)

#### i18next

```yaml
- name: i18next
  category: i18n
  evidence:
    - type: script_src
      pattern: 'i18next(\.min)?\.js'
      confidence: 0.80
    - type: js_global
      pattern: 'i18next|i18n\.t\('
      confidence: 0.85
```

#### Phrase (formerly Phraseapp)

```yaml
- name: Phrase In-Context Editor
  category: i18n
  evidence:
    - type: script_src
      pattern: 'in-context\.phraseapp\.com|phrase\.com'
      confidence: 0.90
```

#### Crowdin In-Context

```yaml
- name: Crowdin In-Context
  category: i18n
  evidence:
    - type: script_src
      pattern: 'crowdin\.com/jipt'
      confidence: 0.95
    - type: js_global
      pattern: '_jipt'
      confidence: 0.90
```

**Pattern explanation:** Translation management platforms inject in-context editing scripts that insert their own global JS objects (`_jipt` for Crowdin) or load assets from their own CDN domains.

---

### Progressive Web App (PWA) Indicators

#### Web App Manifest

```yaml
- name: Web App Manifest (PWA)
  category: PWA
  evidence:
    - type: html_pattern
      pattern: '<link[^>]+rel=["'']manifest["'']'
      confidence: 0.80
```

#### Service Worker Registered

```yaml
- name: Service Worker
  category: PWA
  evidence:
    - type: script_content_pattern
      pattern: 'navigator\.serviceWorker\.register\('
      confidence: 0.90
    - type: html_pattern
      pattern: 'serviceWorker\.register'
      confidence: 0.85
```

#### Workbox (Google's Service Worker Library)

```yaml
- name: Workbox
  category: PWA
  evidence:
    - type: script_src
      pattern: 'workbox'
      confidence: 0.80
    - type: script_content_pattern
      pattern: 'workbox\.routing|workbox\.strategies|importScripts.*workbox'
      confidence: 0.90
```

**Pattern explanation:** A `<link rel="manifest">` tag is required for PWA installability. `navigator.serviceWorker.register()` is the standard call to activate a service worker. Workbox is Google's caching strategy library, identifiable by its module names in service worker scripts.

---

### Accessibility & Testing Tools

#### axe Accessibility Engine

```yaml
- name: axe Accessibility Engine
  category: Accessibility
  evidence:
    - type: script_src
      pattern: 'axe(\.min)?\.js|axe-core'
      confidence: 0.90
    - type: js_global
      pattern: 'axe\.run\|axe\.configure'
      confidence: 0.90
```

#### UserWay Accessibility Widget

```yaml
- name: UserWay Accessibility Widget
  category: Accessibility
  evidence:
    - type: script_src
      pattern: 'cdn\.userway\.org'
      confidence: 0.95
    - type: js_global
      pattern: 'UserWay'
      confidence: 0.90
```

#### Cypress Test Runner Artefacts

```yaml
- name: Cypress Test IDs (Dev/Staging)
  category: Testing
  evidence:
    - type: html_pattern
      pattern: 'data-cy=|data-testid='
      confidence: 0.50
```

**Pattern explanation:** `data-cy` is the Cypress-recommended test selector attribute. Its presence in production HTML may indicate a staging environment or that test attributes were not stripped at build time (low confidence, informational only).

---

### Build Tool Fingerprints

#### Webpack

```yaml
- name: Webpack
  category: Build Tool
  evidence:
    - type: script_content_pattern
      pattern: '__webpack_require__\|webpackChunk'
      confidence: 0.95
    - type: script_src
      pattern: 'webpack\.(min\.)?js'
      confidence: 0.80
```

**Pattern explanation:** Webpack bundles inject the `__webpack_require__` runtime function and a `webpackChunk` global for chunk loading. These strings are embedded in every webpack-compiled output file.

#### Vite

```yaml
- name: Vite
  category: Build Tool
  evidence:
    - type: script_content_pattern
      pattern: '__vite_is_modern_browser|vite/modulepreload-polyfill'
      confidence: 0.95
    - type: html_pattern
      pattern: '<script type="module" src=".*\.js">'
      confidence: 0.40
    - type: html_pattern
      pattern: 'modulepreload'
      confidence: 0.60
```

**Pattern explanation:** Vite outputs `<link rel="modulepreload">` tags for ES module preloading and injects `__vite_is_modern_browser` for legacy polyfill detection. These are specific to Vite's output format.

#### Parcel

```yaml
- name: Parcel
  category: Build Tool
  evidence:
    - type: script_content_pattern
      pattern: 'parcelRequire\|parcel_require'
      confidence: 0.90
```

---

### Monitoring & Observability

#### Datadog RUM

```yaml
- name: Datadog Real User Monitoring
  category: Monitoring
  evidence:
    - type: script_src
      pattern: 'browser-agent\.datadoghq'
      confidence: 0.95
    - type: js_global
      pattern: 'DD_RUM'
      confidence: 0.95
```

#### New Relic Browser Agent

```yaml
- name: New Relic Browser Agent
  category: Monitoring
  evidence:
    - type: script_src
      pattern: 'newrelic\.com|nr-data\.net'
      confidence: 0.90
    - type: js_global
      pattern: 'NREUM|newrelic'
      confidence: 0.90
```

#### OpenTelemetry

```yaml
- name: OpenTelemetry
  category: Observability
  evidence:
    - type: header
      name: traceparent
      pattern: '^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$'
      confidence: 0.85
```

**Pattern explanation:** The `traceparent` header follows the W3C Trace Context specification format. Its presence indicates the application is using a distributed tracing system (Jaeger, Zipkin, OpenTelemetry, etc.).

#### Sentry

```yaml
- name: Sentry
  category: Error Tracking
  evidence:
    - type: script_src
      pattern: 'browser\.sentry-cdn\.com|sentry\.io'
      confidence: 0.95
    - type: js_global
      pattern: 'Sentry\.init\('
      confidence: 0.95
```

---

### Headless Browser & Scraping Defences

#### Cloudflare Bot Score

```yaml
- name: Cloudflare Bot Management
  category: Security
  evidence:
    - type: header
      name: cf-mitigated
      confidence: 0.95
    - type: cookie
      name: cf_bm
      confidence: 0.90
```

#### Kasada

```yaml
- name: Kasada Bot Protection
  category: Security
  evidence:
    - type: script_src
      pattern: 'kasada\.io'
      confidence: 0.95
    - type: header
      name: x-kpsdk-ct
      confidence: 0.95
```

#### PerimeterX / HUMAN Security

```yaml
- name: PerimeterX / HUMAN Security
  category: Security
  evidence:
    - type: script_src
      pattern: 'client\.perimeterx\.net'
      confidence: 0.95
    - type: cookie
      name: _px3
      confidence: 0.90
    - type: cookie
      name: _pxhd
      confidence: 0.85
```

**Pattern explanation:** Advanced bot-mitigation vendors inject challenge cookies (`cf_bm`, `_px3`) and load proprietary sensor scripts from their own CDN domains. These cookies and script URLs are highly specific to each vendor and change in format only between major product versions.

---

*Last updated: March 2026*
