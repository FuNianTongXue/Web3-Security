<template>
  <div class="min-h-screen flex items-center justify-center px-6">
    <div class="w-full max-w-md rounded-2xl border border-line bg-dark/50 p-8">
      <div class="text-2xl font-extrabold text-white">后台登录</div>
      <div class="text-sm text-gray-400 mt-1">请输入管理员 Token</div>

      <input v-model="token" class="mt-6 w-full px-3 py-3 rounded-xl bg-black/30 border border-line text-sm text-gray-100" placeholder="ADMIN_TOKEN" />
      <div v-if="err" class="mt-3 text-sm text-red-300">{{ err }}</div>

      <button @click="login" class="mt-6 w-full px-4 py-3 rounded-xl bg-gold text-black font-semibold hover:brightness-110">登录</button>

      <div class="text-xs text-gray-500 mt-4">
        Token 在 docker-compose.yaml 的 <span class="text-gray-300">ADMIN_TOKEN</span> 中配置。
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'

const router = useRouter()
const token = ref('')
const err = ref('')

async function login() {
  err.value = ''
  if (!token.value) { err.value = '请输入 Token'; return }

  // 用需要鉴权的接口做校验
  const res = await fetch('/api/admin/settings', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', 'X-Admin-Token': token.value },
    body: JSON.stringify({ blogEnabled: 'true' }) // 最小合法字段
  })

  if (res.status === 401) { err.value = 'Token 无效'; return }
  if (!res.ok) {
    // 非 401 的错误也提示（避免“登录成功但进后台空白”）
    const data = await res.json().catch(()=>({}))
    err.value = data.error || '登录校验失败'
    return
  }

  localStorage.setItem('admin_token', token.value)
  router.replace('/admin')
}
</script>
