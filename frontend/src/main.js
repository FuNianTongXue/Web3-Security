import { createApp } from 'vue'
import { createRouter, createWebHistory } from 'vue-router'
import App from './App.vue'
import Home from './views/Home.vue'
import AdminLogin from './views/AdminLogin.vue'
import Admin from './views/Admin.vue'
import ContentPage from './views/ContentPage.vue'
import './assets/tailwind.css'

const routes = [
  { path: '/', component: Home },

  // Content pages (editable via SiteConfig -> pages)
  { path: '/page/:slug', component: ContentPage, props: true },
  { path: '/:module(products|resources|insights|company)', component: ContentPage, props: r => ({ slug: r.params.module }) },

  { path: '/admin', component: Admin, meta: { requiresAuth: true } },
  { path: '/admin/login', component: AdminLogin },

  { path: '/:pathMatch(.*)*', redirect: '/' },
]


const router = createRouter({ history: createWebHistory(), routes })

router.beforeEach((to) => {
  if (to.meta.requiresAuth) {
    const token = localStorage.getItem('admin_token')
    if (!token) return '/admin/login'
  }
})

createApp(App).use(router).mount('#app')
