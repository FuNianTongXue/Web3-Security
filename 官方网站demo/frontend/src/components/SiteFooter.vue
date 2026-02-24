<template>
  <footer class="border-t border-line mt-16">
    <div class="max-w-6xl mx-auto px-6 py-10 grid grid-cols-3 gap-10">
      <div>
        <div class="w-[180px] h-9" v-html="logoSvg"></div>
        <div class="text-xs text-gray-400 mt-3">{{ tagline }}</div>
      </div>

      <div class="text-sm text-gray-300">
        <div class="font-semibold text-gray-100 mb-2">联系方式</div>
        <div v-if="contact.email">Email: <a class="text-gold hover:underline" :href="`mailto:${contact.email}`">{{ contact.email }}</a></div>
        <div v-if="contact.githubUrl">GitHub: <a class="text-gold hover:underline" :href="contact.githubUrl" target="_blank">{{ contact.githubUrl }}</a></div>
        <div v-if="contact.wechatId">微信 ID: <span class="text-gray-100">{{ contact.wechatId }}</span></div>
      </div>

      <div class="text-sm text-gray-300">
        <div class="font-semibold text-gray-100 mb-2">微信 QR</div>
        <div v-if="contact.wechatQrUrl" class="glass rounded-xl p-3 inline-block">
          <img :src="contact.wechatQrUrl" class="w-40 h-40 object-contain" />
        </div>
        <div v-else class="text-xs text-gray-500">No QR uploaded yet.</div>
      </div>
    </div>
    <div class="text-xs text-gray-500 border-t border-line">
      <div class="max-w-6xl mx-auto px-6 py-4">© {{ new Date().getFullYear() }} AurumSec. All rights reserved.</div>
    </div>
  </footer>
</template>

<script setup>
import { computed } from 'vue'
const props = defineProps({ config: { type: Object, required: true }, contact: { type: Object, required: true } })
const logoSvg = computed(() => props.config?.brand?.logo?.value || '')
const tagline = computed(() => props.config?.brand?.tagline || '')
</script>
