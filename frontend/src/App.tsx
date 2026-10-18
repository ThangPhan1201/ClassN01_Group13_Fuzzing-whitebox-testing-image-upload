import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter, Routes, Route, useLocation, Navigate } from 'react-router-dom';
import { Header, Footer } from './components/layout';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import { CartProvider } from './contexts/CartContext';
import {
  HomePage,
  BooksPage,
  BookDetailPage,
  CategoriesPage,
  UniversitiesPage,
  UniversityDetailPage,
  SearchPage,
  LoginPage,
  RegisterPage,
  ListingDetailPage,
  CreateListingPage,
} from './pages';
import { CartPage, CheckoutPage } from './pages/cart';
import { MyOrdersPage, OrderDetailPage, OrderSuccessPage, SellerOrdersPage } from './pages/orders';
import { MockPaymentPage, PaymentSuccessPage, PaymentFailedPage, VnpayReturnPage, BankingConfirmationPage, SandboxPaymentPage } from './pages/payment';
import WalletPage from './pages/wallet/WalletPage';
import RequireAdmin from './pages/admin/RequireAdmin';
import AdminDashboardPage from './pages/admin/AdminDashboardPage';
import AdminUsersPage from './pages/admin/AdminUsersPage';
import AdminListingsPage from './pages/admin/AdminListingsPage';
import FavoritesPage from './pages/FavoritesPage';
import NotificationsPage from './pages/NotificationsPage';
import './index.css';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 1000 * 60 * 5, // 5 minutes
      retry: 1,
    },
  },
});

// Routes without header/footer (auth pages)
const AUTH_ROUTES = ['/login', '/register'];

function RequireAuth({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuth();
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }
  return <>{children}</>;
}

function AppContent() {
  const location = useLocation();
  const isAuthPage = AUTH_ROUTES.includes(location.pathname);

  return (
    <div className="flex flex-col min-h-screen">
      {!isAuthPage && <Header />}
      <main className="flex-1">
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route path="/books" element={<BooksPage />} />
          <Route path="/books/:id" element={<BookDetailPage />} />
          <Route path="/categories" element={<CategoriesPage />} />
          <Route path="/universities" element={<UniversitiesPage />} />
          <Route path="/universities/:id" element={<UniversityDetailPage />} />
          <Route path="/search" element={<SearchPage />} />
          <Route path="/listings/create" element={<RequireAuth><CreateListingPage /></RequireAuth>} />
          <Route path="/listings/:id" element={<ListingDetailPage />} />
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
          <Route path="/cart" element={<CartPage />} />
          <Route path="/checkout" element={<CheckoutPage />} />
          <Route path="/orders" element={<MyOrdersPage />} />
          <Route path="/orders/success" element={<OrderSuccessPage />} />
          <Route path="/orders/:id" element={<OrderDetailPage />} />
          <Route path="/seller/orders" element={<SellerOrdersPage />} />
          <Route path="/payment/mock/:paymentId" element={<MockPaymentPage />} />
          <Route path="/payment/success" element={<PaymentSuccessPage />} />
          <Route path="/payment/failed" element={<PaymentFailedPage />} />
          <Route path="/payment/vnpay/return" element={<VnpayReturnPage />} />
          <Route path="/payment/banking/:orderId" element={<BankingConfirmationPage />} />
          <Route path="/payment/sandbox/:paymentId" element={<SandboxPaymentPage />} />
          <Route path="/wallet" element={<WalletPage />} />
          <Route path="/favorites" element={<RequireAuth><FavoritesPage /></RequireAuth>} />
          <Route path="/notifications" element={<RequireAuth><NotificationsPage /></RequireAuth>} />
          <Route path="/admin" element={<RequireAdmin />}>
            <Route index element={<AdminDashboardPage />} />
            <Route path="users" element={<AdminUsersPage />} />
            <Route path="listings" element={<AdminListingsPage />} />
          </Route>
        </Routes>
      </main>
      {!isAuthPage && <Footer />}
    </div>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AuthProvider>
          <CartProvider>
            <AppContent />
          </CartProvider>
        </AuthProvider>
      </BrowserRouter>
    </QueryClientProvider>
  );
}

export default App;
