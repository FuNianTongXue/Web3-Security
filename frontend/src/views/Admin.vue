<template>
  <div class="max-w-6xl mx-auto px-6 py-10">
    <div class="flex items-center justify-between gap-4">
      <div>
        <div class="text-gold font-semibold">后台管理</div>
        <div class="text-3xl font-bold mt-1">内容维护</div>
        <div class="text-sm text-gray-400 mt-2">维护首页模块、联系方式、站点页面内容。</div>
      </div>

      <div class="flex items-center gap-3">
        <RouterLink to="/" class="px-4 py-2 rounded-xl bg-gold text-black font-semibold text-sm hover:brightness-110">
          查看站点
        </RouterLink>
        <button @click="logout" class="px-4 py-2 rounded-xl border border-line hover:border-gold/50 hover:text-gold text-sm">
          退出登录
        </button>
      </div>
    </div>

    <!-- Tabs -->
    <div class="mt-8 flex flex-wrap gap-2">
      <button v-for="t in tabs" :key="t.key" @click="activeTab=t.key"
              class="px-4 py-2 rounded-xl border text-sm"
              :class="activeTab===t.key ? 'border-gold/60 text-gold bg-white/5' : 'border-line text-gray-200 hover:border-gold/40 hover:text-gold'">
        {{ t.label }}
      </button>
    </div>

    <!-- Products -->
    <section v-if="activeTab==='products'" class="mt-6 glass rounded-3xl p-6">
      <div class="flex items-center justify-between">
        <div>
          <div class="text-gold font-semibold">产品卡片</div>
          <div class="text-sm text-gray-400 mt-1">对应首页「安全 / 合规 / 工具」区域与下拉内容。</div>
        </div>
        <button @click="openNewProduct" class="text-sm px-4 py-2 rounded-xl bg-gold text-black font-semibold hover:brightness-110">
          新增
        </button>
      </div>

      <div class="mt-6 grid grid-cols-2 gap-4">
        <div v-for="p in products" :key="p.id" class="rounded-2xl border border-line p-4 bg-black/20">
          <div class="flex items-start justify-between gap-3">
            <div>
              <div class="font-semibold text-gray-100">{{ p.name }}</div>
              <div class="text-xs text-gray-500 mt-1">分类：{{ categoryLabel(p.category) }}</div>
            </div>
            <div class="flex items-center gap-2">
              <button @click="editProduct(p)" class="text-xs px-3 py-2 rounded-xl border border-line hover:border-gold/40 hover:text-gold">编辑</button>
              <button @click="removeProduct(p)" class="text-xs px-3 py-2 rounded-xl border border-red-500/40 text-red-300 hover:bg-red-500/10">删除</button>
            </div>
          </div>
          <div class="text-sm text-gray-300 mt-3 leading-relaxed">{{ p.description }}</div>
        </div>
      </div>

      <!-- Product Form -->
      <div v-if="showProductForm" class="mt-8 rounded-3xl border border-line p-6 bg-black/25">
        <div class="font-semibold text-gray-100">{{ form.id ? '编辑产品' : '新增产品' }}</div>

        <div class="grid grid-cols-2 gap-4 mt-4">
          <div>
            <div class="text-xs text-gray-400 mb-2">名称</div>
            <input v-model="form.name" class="w-full px-3 py-2 rounded-xl bg-black/30 border border-line outline-none focus:border-gold/40" placeholder="例如：链上威胁监测" />
          </div>
          <div>
            <div class="text-xs text-gray-400 mb-2">分类</div>
            <select v-model="form.category" class="w-full px-3 py-2 rounded-xl bg-black/30 border border-line outline-none focus:border-gold/40">
              <option value="SECURITY">安全</option>
              <option value="COMPLIANCE">合规</option>
              <option value="TOOLS">工具</option>
            </select>
          </div>
        </div>

        <div class="mt-4">
          <div class="text-xs text-gray-400 mb-2">描述</div>
          <textarea v-model="form.description" rows="4" class="w-full px-3 py-2 rounded-xl bg-black/30 border border-line outline-none focus:border-gold/40"
                    placeholder="一句话说明这个能力/产品是什么"></textarea>
        </div>

        <div class="mt-4 flex items-center gap-3">
          <button @click="saveProduct" class="px-4 py-2 rounded-xl bg-gold text-black font-semibold text-sm hover:brightness-110">保存</button>
          <button @click="cancelProduct" class="px-4 py-2 rounded-xl border border-line text-sm hover:border-gold/40 hover:text-gold">取消</button>
          <div v-if="productMsg" class="text-sm" :class="productOk ? 'text-green-400' : 'text-red-400'">{{ productMsg }}</div>
        </div>
      </div>
    </section>

    <!-- Pages -->
    <section v-if="activeTab==='pages'" class="mt-6 glass rounded-3xl p-6">
      <div class="text-gold font-semibold">页面内容</div>
      <div class="text-sm text-gray-400 mt-1">模块页：/products /resources /insights /company；自定义页：/page/&lt;slug&gt;。</div>

      <div class="mt-6">
        <div class="font-semibold text-gray-100">模块页（快速编辑）</div>
        <div class="grid grid-cols-2 gap-4 mt-4">
          <div v-for="p in pageEditors" :key="p.slug" class="rounded-2xl border border-line p-4 bg-black/20">
            <div class="flex items-center justify-between">
              <div class="font-semibold text-gray-100">{{ p.titleLabel }}</div>
              <div class="text-xs text-gray-500">slug: {{ p.slug }}</div>
            </div>
            <input v-model="p.title" class="mt-3 w-full px-3 py-2 rounded-xl bg-black/30 border border-line text-sm" placeholder="页面标题" />
            <textarea v-model="p.contentHtml" rows="8"
                      class="mt-3 w-full px-3 py-2 rounded-xl bg-black/30 border border-line text-sm font-mono"
                      placeholder="内容（支持 HTML，例如 <p>...</p>）"></textarea>
          </div>
        </div>

        <div class="mt-4 flex items-center gap-3">
          <button @click="savePagesQuick" class="px-4 py-2 rounded-xl bg-gold text-black font-semibold text-sm hover:brightness-110">保存模块页</button>
          <div v-if="pagesMsg" class="text-sm" :class="pagesOk ? 'text-green-400' : 'text-red-400'">{{ pagesMsg }}</div>
        </div>
      </div>

      <div class="mt-10">
        <div class="font-semibold text-gray-100">自定义页面管理</div>

        <div class="grid grid-cols-2 gap-4 mt-4">
          <div class="rounded-2xl border border-line p-4 bg-black/20">
            <div class="font-semibold text-gray-100">新增页面</div>
            <input v-model="newPage.slug" class="mt-3 w-full px-3 py-2 rounded-xl bg-black/30 border border-line text-sm" placeholder="slug（如 my-page）" />
            <input v-model="newPage.title" class="mt-3 w-full px-3 py-2 rounded-xl bg-black/30 border border-line text-sm" placeholder="标题" />
            <textarea v-model="newPage.contentHtml" rows="8" class="mt-3 w-full px-3 py-2 rounded-xl bg-black/30 border border-line text-sm font-mono" placeholder="内容（支持 HTML）"></textarea>
            <button @click="addPage" class="mt-3 px-4 py-2 rounded-xl bg-gold text-black font-semibold text-sm hover:brightness-110">新增</button>
          </div>

          <div class="rounded-2xl border border-line p-4 bg-black/20">
            <div class="flex items-center justify-between">
              <div class="font-semibold text-gray-100">已有页面</div>
              <div class="text-xs text-gray-500">点击选择编辑</div>
            </div>
            <div class="mt-3 max-h-[360px] overflow-auto">
              <button v-for="k in pageKeys" :key="k" @click="selectPage(k)"
                      class="block w-full text-left px-3 py-2 rounded-xl border border-line/50 bg-black/20 hover:bg-white/5 text-sm">
                {{ k }}
              </button>
            </div>
          </div>
        </div>

        <div v-if="selectedPageKey" class="rounded-2xl border border-line p-4 bg-black/20 mt-6">
          <div class="flex items-center justify-between">
            <div class="font-semibold text-gray-100">编辑页面：{{ selectedPageKey }}</div>
            <button @click="deletePage" class="text-xs px-3 py-2 rounded-xl border border-red-500/40 text-red-300 hover:bg-red-500/10">删除</button>
          </div>

          <input v-model="selectedPage.title" class="mt-3 w-full px-3 py-2 rounded-xl bg-black/30 border border-line text-sm" placeholder="标题" />
          <textarea v-model="selectedPage.contentHtml" rows="10" class="mt-3 w-full px-3 py-2 rounded-xl bg-black/30 border border-line text-sm font-mono" placeholder="内容（支持 HTML）"></textarea>

          <div class="mt-3 flex items-center gap-3">
            <button @click="saveSelectedPage" class="px-4 py-2 rounded-xl bg-gold text-black font-semibold text-sm hover:brightness-110">保存</button>
            <a class="text-xs text-gold hover:brightness-110" :href="'/page/'+selectedPageKey" target="_blank">打开预览 →</a>
            <div v-if="pageMgrMsg" class="text-sm" :class="pageMgrOk ? 'text-green-400' : 'text-red-400'">{{ pageMgrMsg }}</div>
          </div>
        </div>
      </div>

      <div class="mt-10">
        <div class="font-semibold text-gray-100">站点配置（JSON）</div>
        <div class="text-sm text-gray-400 mt-1">高级选项：直接编辑 JSON（谨慎）。</div>
        <textarea v-model="siteConfigText" rows="14"
                  class="mt-4 w-full px-3 py-2 rounded-xl bg-black/30 border border-line text-sm font-mono outline-none focus:border-gold/40"></textarea>

        <div class="mt-3 flex items-center gap-3">
          <button @click="saveSiteConfig" class="px-4 py-2 rounded-xl bg-gold text-black font-semibold text-sm hover:brightness-110">保存 JSON</button>
          <button @click="reloadSiteConfig" class="px-4 py-2 rounded-xl border border-line text-sm hover:border-gold/40 hover:text-gold">重新加载</button>
          <div v-if="siteConfigMsg" class="text-sm" :class="siteConfigOk ? 'text-green-400' : 'text-red-400'">{{ siteConfigMsg }}</div>
        </div>
      </div>
    </section>

    <!-- Contact -->
    <section v-if="activeTab==='contact'" class="mt-6 glass rounded-3xl p-6">
      <div class="text-gold font-semibold">联系方式</div>
      <div class="text-sm text-gray-400 mt-1">用于页脚与联系区展示。</div>

      <div class="grid grid-cols-2 gap-4 mt-6">
        <div>
          <div class="text-xs text-gray-400 mb-2">邮箱</div>
          <input v-model="contact.email" class="w-full px-3 py-2 rounded-xl bg-black/30 border border-line outline-none focus:border-gold/40" placeholder="email@example.com" />
        </div>
        <div>
          <div class="text-xs text-gray-400 mb-2">GitHub 链接</div>
          <input v-model="contact.githubUrl" class="w-full px-3 py-2 rounded-xl bg-black/30 border border-line outline-none focus:border-gold/40" placeholder="https://github.com/xxx" />
        </div>
        <div>
          <div class="text-xs text-gray-400 mb-2">微信号</div>
          <input v-model="contact.wechatId" class="w-full px-3 py-2 rounded-xl bg-black/30 border border-line outline-none focus:border-gold/40" placeholder="WeChat ID" />
        </div>
        <div>
          <div class="text-xs text-gray-400 mb-2">微信二维码图片 URL</div>
          <input v-model="contact.wechatQrUrl" class="w-full px-3 py-2 rounded-xl bg-black/30 border border-line outline-none focus:border-gold/40" placeholder="/uploads/xxx.png 或 https://..." />
        </div>
      </div>

      <div class="mt-6 flex items-center gap-3">
        <input ref="fileInput" type="file" class="hidden" @change="uploadQr" />
        <button @click="fileInput?.click()" class="px-4 py-2 rounded-xl border border-line text-sm hover:border-gold/40 hover:text-gold">上传二维码</button>
        <button @click="saveContact" class="px-4 py-2 rounded-xl bg-gold text-black font-semibold text-sm hover:brightness-110">保存</button>
        <div v-if="contactMsg" class="text-sm text-green-400">{{ contactMsg }}</div>
      </div>

      <div v-if="contact.wechatQrUrl" class="mt-6">
        <div class="text-xs text-gray-400 mb-2">预览</div>
        <img :src="contact.wechatQrUrl" class="w-40 h-40 object-contain rounded-2xl border border-line bg-black/30" />
      </div>
    </section>

    <!-- Settings -->
    <section v-if="activeTab==='settings'" class="mt-6 glass rounded-3xl p-6">
      <div class="text-gold font-semibold">站点设置</div>
      <div class="text-sm text-gray-400 mt-1">开关与基础文案。</div>

      <div class="mt-6 grid grid-cols-2 gap-4">
        <label class="flex items-center gap-3 rounded-2xl border border-line p-4 bg-black/20">
          <input type="checkbox" v-model="blogEnabled" />
          <div>
            <div class="font-semibold text-gray-100">启用「资源-行业博客」</div>
            <div class="text-xs text-gray-500 mt-1">开关仅示例，可按需扩展更多设置。</div>
          </div>
        </label>
      </div>

      <div class="mt-6 flex items-center gap-3">
        <button @click="saveSettings" class="px-4 py-2 rounded-xl bg-gold text-black font-semibold text-sm hover:brightness-110">保存</button>
        <div v-if="settingsMsg" class="text-sm" :class="settingsOk ? 'text-green-400' : 'text-red-400'">{{ settingsMsg }}</div>
      </div>
    </section>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { RouterLink, useRouter } from 'vue-router'

const router = useRouter()
const token = () => localStorage.getItem('admin_token') || ''

function headers(extra = {}) {
  return { 'Content-Type': 'application/json', 'X-Admin-Token': token(), ...extra }
}

function logout() {
  localStorage.removeItem('admin_token')
  router.replace('/admin/login')
}

const tabs = [
  { key: 'products', label: '产品' },
  { key: 'pages', label: '页面' },
  { key: 'contact', label: '联系方式' },
  { key: 'settings', label: '设置' },
]
const activeTab = ref('products')

/** Products */
const products = ref([])
const showProductForm = ref(false)
const form = reactive({ id: null, name: '', description: '', category: 'SECURITY' })
const productMsg = ref('')
const productOk = ref(true)

function categoryLabel(c) {
  if (c === 'SECURITY') return '安全'
  if (c === 'COMPLIANCE') return '合规'
  if (c === 'TOOLS') return '工具'
  return c
}

async function loadProducts() {
  products.value = await fetch('/api/products').then(r => r.json())
}
function openNewProduct() {
  productMsg.value = ''
  form.id = null
  form.name = ''
  form.description = ''
  form.category = 'SECURITY'
  showProductForm.value = true
}
function editProduct(p) {
  productMsg.value = ''
  form.id = p.id
  form.name = p.name
  form.description = p.description
  form.category = p.category
  showProductForm.value = true
}
function cancelProduct() { showProductForm.value = false }

async function saveProduct() {
  productMsg.value = ''
  productOk.value = true
  if (!form.name.trim()) { productOk.value = false; productMsg.value = '名称不能为空'; return }
  const payload = { name: form.name.trim(), description: form.description.trim(), category: form.category }
  const res = await fetch(form.id ? `/api/admin/products/${form.id}` : '/api/admin/products', {
    method: form.id ? 'PUT' : 'POST',
    headers: headers(),
    body: JSON.stringify(payload)
  })
  if (res.status === 401) return router.replace('/admin/login')
  const data = await res.json().catch(() => ({}))
  productOk.value = res.ok
  productMsg.value = res.ok ? '已保存。' : (data.error || '保存失败')
  if (res.ok) {
    showProductForm.value = false
    await loadProducts()
  }
}

async function removeProduct(p) {
  if (!confirm(`确定删除：${p.name} ?`)) return
  const res = await fetch(`/api/admin/products/${p.id}`, { method: 'DELETE', headers: headers() })
  if (res.status === 401) return router.replace('/admin/login')
  await loadProducts()
}

/** Contact */
const contact = reactive({ email: '', githubUrl: '', wechatId: '', wechatQrUrl: '' })
const contactMsg = ref('')
const fileInput = ref(null)

async function loadContact() {
  Object.assign(contact, await fetch('/api/contact').then(r => r.json()))
}
async function saveContact() {
  contactMsg.value = ''
  const res = await fetch('/api/admin/contact', { method: 'PUT', headers: headers(), body: JSON.stringify(contact) })
  if (res.status === 401) return router.replace('/admin/login')
  contactMsg.value = res.ok ? '已保存。' : '保存失败'
  await loadContact()
}
async function uploadQr(e) {
  const file = e.target.files?.[0]
  if (!file) return
  const fd = new FormData()
  fd.append('file', file)
  const res = await fetch('/api/admin/upload', { method: 'POST', headers: { 'X-Admin-Token': token() }, body: fd })
  if (res.status === 401) return router.replace('/admin/login')
  const data = await res.json().catch(() => ({}))
  if (res.ok && data.url) {
    contact.wechatQrUrl = data.url
    contactMsg.value = '上传成功，记得点击保存。'
  } else {
    contactMsg.value = data.error || '上传失败'
  }
  e.target.value = ''
}

/** Settings */
const blogEnabled = ref(false)
const settingsMsg = ref('')
const settingsOk = ref(true)

async function loadSettings() {
  const s = await fetch('/api/settings').then(r => r.json())
  blogEnabled.value = s.blogEnabled === 'true'
}
async function saveSettings() {
  settingsMsg.value = ''
  settingsOk.value = true
  const res = await fetch('/api/admin/settings', { method: 'PUT', headers: headers(), body: JSON.stringify({ blogEnabled: String(blogEnabled.value) }) })
  if (res.status === 401) return router.replace('/admin/login')
  const data = await res.json().catch(() => ({}))
  settingsOk.value = res.ok
  settingsMsg.value = res.ok ? '已保存。' : (data.error || '保存失败')
  await loadSettings()
}

/** SiteConfig & Pages */
const siteConfigText = ref('')
const siteConfigMsg = ref('')
const siteConfigOk = ref(true)

async function reloadSiteConfig() {
  const sc = await fetch('/api/site-config').then(r => r.json())
  siteConfigText.value = JSON.stringify(sc, null, 2)
  // populate quick editors
  const pages = sc.pages || {}
  for (const pe of pageEditors.value) {
    const obj = pages[pe.slug] || {}
    pe.title = obj.title || ''
    pe.contentHtml = obj.contentHtml || ''
  }
}

async function saveSiteConfig() {
  siteConfigMsg.value = ''
  siteConfigOk.value = true
  let obj
  try { obj = JSON.parse(siteConfigText.value || '{}') } catch {
    siteConfigOk.value = false
    siteConfigMsg.value = 'JSON 解析失败'
    return
  }
  const res = await fetch('/api/admin/site-config', { method: 'PUT', headers: headers(), body: JSON.stringify(obj) })
  if (res.status === 401) return router.replace('/admin/login')
  const data = await res.json().catch(() => ({}))
  siteConfigOk.value = res.ok
  siteConfigMsg.value = res.ok ? '已保存。' : (data.error || '保存失败')
  if (res.ok) await reloadSiteConfig()
}

const pagesMsg = ref('')
const pagesOk = ref(true)
const pageEditors = ref([
  { slug: 'products', titleLabel: '产品', title: '', contentHtml: '' },
  { slug: 'resources', titleLabel: '资源', title: '', contentHtml: '' },
  { slug: 'insights', titleLabel: '洞察', title: '', contentHtml: '' },
  { slug: 'company', titleLabel: '公司', title: '', contentHtml: '' },
])

async function savePagesQuick() {
  pagesMsg.value = ''
  pagesOk.value = true
  let sc
  try { sc = JSON.parse(siteConfigText.value || '{}') } catch {
    pagesOk.value = false
    pagesMsg.value = '站点配置 JSON 无法解析'
    return
  }
  sc.pages = sc.pages || {}
  for (const pe of pageEditors.value) {
    sc.pages[pe.slug] = { title: pe.title || pe.titleLabel, contentHtml: pe.contentHtml || '' }
  }
  const res = await fetch('/api/admin/site-config', { method: 'PUT', headers: headers(), body: JSON.stringify(sc) })
  if (res.status === 401) return router.replace('/admin/login')
  const data = await res.json().catch(() => ({}))
  pagesOk.value = res.ok
  pagesMsg.value = res.ok ? '已保存。' : (data.error || '保存失败')
  if (res.ok) siteConfigText.value = JSON.stringify(sc, null, 2)
}

/** Page manager */
const newPage = ref({ slug: '', title: '', contentHtml: '' })
const selectedPageKey = ref('')
const selectedPage = ref({ title: '', contentHtml: '' })
const pageMgrMsg = ref('')
const pageMgrOk = ref(true)

const pageKeys = computed(() => {
  try {
    const sc = JSON.parse(siteConfigText.value || '{}')
    return Object.keys(sc.pages || {}).sort()
  } catch {
    return []
  }
})

function selectPage(k) {
  selectedPageKey.value = k
  let sc
  try { sc = JSON.parse(siteConfigText.value || '{}') } catch { return }
  const obj = (sc.pages || {})[k] || { title: '', contentHtml: '' }
  selectedPage.value = { title: obj.title || '', contentHtml: obj.contentHtml || '' }
}

async function addPage() {
  pageMgrMsg.value = ''
  pageMgrOk.value = true
  const slug = (newPage.value.slug || '').trim()
  if (!slug) { pageMgrOk.value = false; pageMgrMsg.value = 'slug 不能为空'; return }
  let sc
  try { sc = JSON.parse(siteConfigText.value || '{}') } catch { pageMgrOk.value = false; pageMgrMsg.value = '站点配置 JSON 无法解析'; return }
  sc.pages = sc.pages || {}
  if (sc.pages[slug]) { pageMgrOk.value = false; pageMgrMsg.value = '该 slug 已存在'; return }
  sc.pages[slug] = { title: newPage.value.title || slug, contentHtml: newPage.value.contentHtml || '' }

  const res = await fetch('/api/admin/site-config', { method: 'PUT', headers: headers(), body: JSON.stringify(sc) })
  if (res.status === 401) return router.replace('/admin/login')
  const data = await res.json().catch(() => ({}))
  pageMgrOk.value = res.ok
  pageMgrMsg.value = res.ok ? '已新增。' : (data.error || '新增失败')
  if (res.ok) {
    siteConfigText.value = JSON.stringify(sc, null, 2)
    newPage.value = { slug: '', title: '', contentHtml: '' }
    selectPage(slug)
  }
}

async function saveSelectedPage() {
  pageMgrMsg.value = ''
  pageMgrOk.value = true
  if (!selectedPageKey.value) return
  let sc
  try { sc = JSON.parse(siteConfigText.value || '{}') } catch { pageMgrOk.value = false; pageMgrMsg.value = '站点配置 JSON 无法解析'; return }
  sc.pages = sc.pages || {}
  sc.pages[selectedPageKey.value] = { title: selectedPage.value.title || selectedPageKey.value, contentHtml: selectedPage.value.contentHtml || '' }

  const res = await fetch('/api/admin/site-config', { method: 'PUT', headers: headers(), body: JSON.stringify(sc) })
  if (res.status === 401) return router.replace('/admin/login')
  const data = await res.json().catch(() => ({}))
  pageMgrOk.value = res.ok
  pageMgrMsg.value = res.ok ? '已保存。' : (data.error || '保存失败')
  if (res.ok) siteConfigText.value = JSON.stringify(sc, null, 2)
}

async function deletePage() {
  pageMgrMsg.value = ''
  pageMgrOk.value = true
  const k = selectedPageKey.value
  if (!k) return
  let sc
  try { sc = JSON.parse(siteConfigText.value || '{}') } catch { pageMgrOk.value = false; pageMgrMsg.value = '站点配置 JSON 无法解析'; return }
  sc.pages = sc.pages || {}
  delete sc.pages[k]

  const res = await fetch('/api/admin/site-config', { method: 'PUT', headers: headers(), body: JSON.stringify(sc) })
  if (res.status === 401) return router.replace('/admin/login')
  const data = await res.json().catch(() => ({}))
  pageMgrOk.value = res.ok
  pageMgrMsg.value = res.ok ? '已删除。' : (data.error || '删除失败')
  if (res.ok) {
    siteConfigText.value = JSON.stringify(sc, null, 2)
    selectedPageKey.value = ''
    selectedPage.value = { title: '', contentHtml: '' }
  }
}

onMounted(async () => {
  await Promise.all([loadProducts(), loadContact(), loadSettings(), reloadSiteConfig()])
})
</script>
