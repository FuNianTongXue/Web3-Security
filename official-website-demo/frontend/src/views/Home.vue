<template>
  <div>
    <HeaderMega v-if="siteConfig" :config="siteConfig" />
    <main class="max-w-6xl mx-auto px-6 py-16">
      <section class="grid grid-cols-2 gap-10 items-center">
        <div>
          <h1 class="text-5xl font-extrabold leading-tight">{{ hero.headline }}</h1>
          <div class="text-gray-300 text-lg mt-5">{{ hero.subhead }}</div>

          <div class="mt-8 flex items-center gap-3">
            <a :href="hero.secondaryCta.href" class="px-5 py-3 rounded-xl border border-line hover:border-gold/50 hover:text-gold">
              {{ hero.secondaryCta.label }}
            </a>
            <a :href="hero.primaryCta.href" class="px-5 py-3 rounded-xl bg-gold text-black font-semibold hover:brightness-110">
              {{ hero.primaryCta.label }}
            </a>
          </div>
          <div class="text-xs text-gray-400 mt-3">{{ hero.note }}</div>
        </div>

        <div class="glass rounded-3xl p-8 relative overflow-hidden">
          <div class="absolute -right-20 -top-20 w-72 h-72 bg-gold/20 blur-3xl rounded-full"></div>
          <div class="absolute -left-20 -bottom-20 w-72 h-72 bg-blue-500/10 blur-3xl rounded-full"></div>
          <div class="text-sm text-gray-300">特色能力</div>
          <div class="mt-2 text-2xl font-bold text-white">攻击路径 · 资金流向 · 模拟推演</div>
          <div class="mt-3 text-sm text-gray-400 leading-relaxed">
            Build a secure and seamless Web3 experience with real-time monitoring, compliance intelligence, and developer-friendly tooling.
          </div>
          <div class="mt-6 grid grid-cols-2 gap-4">
            <div class="rounded-2xl border border-line p-4">
              <div class="text-gold font-semibold">Real-time</div>
              <div class="text-xs text-gray-400 mt-1">Alert what matters and respond fast.</div>
            </div>
            <div class="rounded-2xl border border-line p-4">
              <div class="text-gold font-semibold">合规</div>
              <div class="text-xs text-gray-400 mt-1">地址筛查与 AML 风险识别。</div>
            </div>
          </div>
        </div>
      </section>

      <section class="mt-16">
        <div class="flex items-end justify-between">
          <div>
            <div class="text-gold font-semibold">产品</div>
            <div class="text-2xl font-bold mt-1">安全 · 合规 · 工具</div>
            <div class="text-sm text-gray-400 mt-2">可在后台管理修改。</div>
          </div>
          <a href="/admin" class="text-xs text-gray-400 hover:text-gold">后台管理 →</a>
        </div>

        <div class="mt-6 grid grid-cols-3 gap-5">
          <div v-for="p in products" :key="p.id" class="glass rounded-2xl p-5 hover:border-gold/30 border border-line transition">
            <div class="text-xs text-gray-400">{{ p.category }}</div>
            <div class="text-lg font-semibold mt-1">{{ p.name }}</div>
            <div class="text-sm text-gray-400 mt-2 leading-relaxed">{{ p.description }}</div>
          </div>
        </div>
      </section>

      <section class="mt-16 glass rounded-3xl p-8">
        <div class="text-gold font-semibold">Contact</div>
        <div class="grid grid-cols-3 gap-6 mt-4 text-sm text-gray-200">
          <div>
            <div class="text-gray-400 text-xs">Email</div>
            <div class="mt-1">{{ contact.email }}</div>
          </div>
          <div>
            <div class="text-gray-400 text-xs">GitHub</div>
            <div class="mt-1 truncate">{{ contact.githubUrl }}</div>
          </div>
          <div>
            <div class="text-gray-400 text-xs">WeChat</div>
            <div class="mt-1">{{ contact.wechatId }}</div>
          </div>
        </div>
      </section>
    </main>

    <SiteFooter v-if="siteConfig" :config="siteConfig" :contact="contact" />
  </div>
</template>

<script setup>
import { onMounted, ref, computed } from 'vue'
import HeaderMega from '../components/HeaderMega.vue'
import SiteFooter from '../components/SiteFooter.vue'

const siteConfig = ref(null)
const products = ref([])
const contact = ref({})

const hero = computed(() => siteConfig.value?.home?.hero || {
  headline: '构建安全且无缝的 Web3 世界',
  subhead: 'Full-Stack Blockchain Security and 合规 Provider',
  primaryCta: {label:'启动平台', href:'#'},
  secondaryCta: {label:'申请审计', href:'#'},
  note: 'Get started for free',
})

async function loadAll() {
  const [sc, ps, ci] = await Promise.all([
    fetch('/api/site-config').then(r => r.json()),
    fetch('/api/products').then(r => r.json()),
    fetch('/api/contact').then(r => r.json()),
  ])
  siteConfig.value = sc
  products.value = ps
  contact.value = ci
}

onMounted(loadAll)
</script>
