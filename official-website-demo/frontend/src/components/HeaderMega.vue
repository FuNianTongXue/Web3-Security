<template>
  <header class="sticky top-0 z-60 bg-dark/70 backdrop-blur border-b border-line">
    <!-- Dim & blur the background while mega menu is open to improve readability -->
    <div v-if="open" class="menu-overlay" @click="open = ''; pinnedKey.value = ''"></div>
    <div class="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
      <div class="w-[180px] h-9" v-html="logoSvg"></div>

            <nav class="flex items-center gap-6 text-sm text-gray-200">
        <template v-for="item in nav" :key="item.label">
          <!-- Mega menu (hover opens, click navigates) -->
          <div
            v-if="item.type==='mega'"
            class="relative"
            @mouseenter="onEnter(item.key)"
            @mouseleave="onLeave(item.key)"
          >
            <button type="button" class="hover:text-gold" @click="togglePinned(item.key)">{{ item.label }}</button>

            <!-- 产品下拉 -->
            <div
              v-if="open===item.key && item.key==='products'"
              class="absolute left-1/2 -translate-x-1/2 mt-4 w-[860px] glass mega-menu-panel rounded-2xl p-6"
            >
              <div class="flex items-center justify-between mb-4">
                <div class="text-sm text-gray-300">产品与能力</div>
                <RouterLink to="/products" class="text-xs text-gold hover:brightness-110">查看全部 →</RouterLink>
              </div>
              <div class="grid grid-cols-3 gap-6">
                <div v-for="col in mega.products.columns" :key="col.title">
                  <div class="text-xs tracking-widest mm-group mb-3">{{ col.title }}</div>
                  <RouterLink v-for="it in col.items" :key="it.title" :to="it.href" class="block rounded-xl px-4 py-3 hover:bg-white/5">
                    <div class="flex items-center justify-between">
                      <div class="font-semibold mm-title">{{ it.title }}</div>
                      <span v-if="it.badge" class="text-[10px] px-2 py-1 rounded-full bg-gold/20 text-gold border border-gold/30">
                        {{ it.badge }}
                      </span>
                    </div>
                    <div class="text-xs mm-desc mt-1">{{ it.desc }}</div>
                  </RouterLink>
                </div>
              </div>
            </div>

            <!-- 洞察下拉 -->
            <div
              v-if="open===item.key && item.key==='insights'"
              class="absolute left-1/2 -translate-x-1/2 mt-4 w-[860px] glass mega-menu-panel rounded-2xl p-6"
            >
              <div class="flex items-center justify-between mb-4">
                <div class="text-sm text-gray-300">洞察与研究</div>
                <RouterLink to="/insights" class="text-xs text-gold hover:brightness-110">查看全部 →</RouterLink>
              </div>
              <div class="grid grid-cols-3 gap-6 items-start">
                <div class="col-span-2 grid grid-cols-2 gap-4">
                  <RouterLink
                    v-for="it in mega.insights.columns"
                    :key="it.title"
                    :to="it.href"
                    class="block rounded-2xl border border-line p-4 hover:bg-white/5"
                  >
                    <div class="text-sm font-semibold mm-title">{{ it.title }}</div>
                    <div class="text-xs mm-desc mt-2">{{ it.desc }}</div>
                  </RouterLink>
                </div>

                <RouterLink :to="mega.insights.featured.href" class="block rounded-2xl border border-line p-4 hover:bg-white/5">
                  <div class="text-xs mm-desc mb-2">手册</div>
                  <div class="font-semibold leading-tight mm-title">{{ mega.insights.featured.title }}</div>
                  <div class="text-gold text-xs mt-2 flex items-center gap-1">
                    {{ mega.insights.featured.ctaLabel }} <span>↗</span>
                  </div>
                </RouterLink>
              </div>
            </div>
          </div>

          <!-- Normal link -->
          <RouterLink v-else class="hover:text-gold" :to="item.href">{{ item.label }}</RouterLink>
        </template>
      </nav>

      <div class="flex items-center gap-3">
        <a :href="cta.secondary.href" class="px-4 py-2 rounded-xl border border-line hover:border-gold/50 hover:text-gold">
          {{ cta.secondary.label }}
        </a>
        <a :href="cta.primary.href" class="px-4 py-2 rounded-xl bg-gold text-black font-semibold hover:brightness-110">
          {{ cta.primary.label }}
        </a>
      </div>
    </div>
  </header>
</template>

<script setup>
import { computed, ref } from 'vue'
import { RouterLink } from 'vue-router'
const props = defineProps({ config: { type: Object, required: true } })
const nav = computed(() => props.config?.header?.nav || [])
const open = ref('')
const pinnedKey = ref('')

function togglePinned(key){
  if(pinnedKey.value===key){ pinnedKey.value=''; open.value=''; return }
  pinnedKey.value = key
  open.value = key
}

function onEnter(key){
  if(!pinnedKey.value) open.value = key
}
function onLeave(key){
  if(!pinnedKey.value) open.value = ''
}

const logoSvg = computed(() => props.config?.brand?.logo?.value || `<div class="text-xl font-bold text-gold">${props.config?.brand?.name || 'AurumSec'}</div>`)
const mega = computed(() => props.config?.megaMenus || { products: { columns: [] }, insights: { columns: [], featured: {} } })
const cta = computed(() => props.config?.header?.cta || { primary: {label:'Launch', href:'#'}, secondary:{label:'Request', href:'#'} })
</script>
