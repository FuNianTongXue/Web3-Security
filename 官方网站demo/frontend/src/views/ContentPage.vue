<template>
  <div>
    <HeaderMega v-if="siteConfig" :config="siteConfig" />
    <main class="max-w-5xl mx-auto px-6 py-14">
      <div class="mb-8">
        <div class="text-xs tracking-widest text-gold/80 uppercase">AurumSec</div>
        <h1 class="text-4xl font-extrabold mt-2">{{ pageTitle }}</h1>
        <div v-if="pageHint" class="text-sm text-gray-400 mt-3">{{ pageHint }}</div>
      </div>

      <article class="content-card" v-html="pageHtml"></article>

      <div class="mt-10 text-sm text-gray-500">
        <a class="hover:text-gold" href="/admin">后台管理 →</a>
      </div>
    </main>
  </div>
</template>

<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import HeaderMega from '../components/HeaderMega.vue'

const props = defineProps({
  slug: { type: String, default: '' },
  hint: { type: String, default: '' },
})

const route = useRoute()
const siteConfig = ref(null)

const actualSlug = computed(() => props.slug || route.params.slug || route.params.module || '')
const pageHint = computed(() => props.hint || '')

const pageObj = computed(() => {
  const pages = siteConfig.value?.pages || {}
  return pages[actualSlug.value] || null
})

const pageTitle = computed(() => pageObj.value?.title || '页面')
const pageHtml = computed(() => pageObj.value?.contentHtml || '<p>该页面暂无内容。请到后台管理 → 站点配置（JSON）中补充 SiteConfig.pages 内容，或使用“页面内容（快速编辑）”。</p>')

async function load() {
  siteConfig.value = await fetch('/api/site-config').then(r => r.json())
}

watch(actualSlug, load)
onMounted(load)
</script>

<style scoped>
.content-card{
  background: rgba(12,12,14,0.7);
  border: 1px solid rgba(255,200,40,0.14);
  border-radius: 18px;
  padding: 22px;
  box-shadow: 0 24px 70px rgba(0,0,0,0.45);
}
.content-card :deep(h2){
  margin-top: 14px;
  margin-bottom: 8px;
  font-size: 20px;
  font-weight: 800;
}
.content-card :deep(h3){
  margin-top: 14px;
  margin-bottom: 8px;
  font-size: 16px;
  font-weight: 700;
}
.content-card :deep(p){
  color: rgba(255,255,255,0.78);
  line-height: 1.7;
  margin: 8px 0;
}
.content-card :deep(ul){
  margin: 10px 0 10px 18px;
  color: rgba(255,255,255,0.75);
  line-height: 1.7;
  list-style: disc;
}
.content-card :deep(a){
  color: rgba(255,200,40,0.9);
}
</style>
