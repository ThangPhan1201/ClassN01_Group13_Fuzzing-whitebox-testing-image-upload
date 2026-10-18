# Downloads (Pre-packaged Archives)

Các file nén `.zip` để tải nhanh toàn bộ dự án về máy khác mà không cần clone git.

## Danh sách file

| File | Nội dung | Kích thước (xấp xỉ) |
| --- | --- | --- |
| `fuzzing-white-box-full.zip` | Tất cả: backend + frontend + fuzz | ~1.2 MB |
| `backend.zip` | Chỉ NestJS API server | ~355 KB |
| `frontend.zip` | Chỉ React app | ~282 KB |
| `fuzz.zip` | Chỉ module fuzzing (image-upload + listing) | ~637 KB |

## Giải nén

### macOS / Linux

```bash
unzip fuzzing-white-box-full.zip
# hoặc từng phần:
unzip backend.zip
unzip frontend.zip
unzip fuzz.zip
```

### Windows

Click chuột phải vào file `.zip` → **Extract All...**

## Lưu ý quan trọng

Các bản zip này **đã loại bỏ** `node_modules`, `dist`, `coverage`, và `.env` để giảm dung lượng. Sau khi giải nén, cần cài lại dependencies:

```bash
# Backend
cd backend
npm install
cp .env.example .env       # rồi chỉnh các biến môi trường
npm run db:generate
npm run db:migrate

# Frontend
cd ../frontend
npm install
cp .env.example .env

# Fuzzing (Python)
cd ../fuzz/image-upload
pip install -r requirements.txt
```

## Cấu trúc sau khi giải nén

```
fuzzing-white-box/
├── backend/      # NestJS API (Prisma + PostgreSQL)
├── frontend/     # React + Vite + Tailwind
├── fuzz/
│   ├── image-upload/   # Module fuzzing ảnh (v1 + v2)
│   └── listing/        # Module fuzzing listing
├── docs/
├── docker-compose.yml
└── .env.example
```

## Truy cập nhanh

| Service | URL |
| --- | --- |
| Frontend | <http://localhost:5173> |
| Backend API | <http://localhost:3000> |
| Swagger | <http://localhost:3000/api/docs> |

Tài khoản demo: `admin@demo.local` / `Demo123!`
