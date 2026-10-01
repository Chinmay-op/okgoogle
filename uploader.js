//File upload
const multer = require("multer");
const fs = require("fs");
const path = require("path");

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null,"./uploads");
    },
    filename: function (req, file, cb){
        return cb(null,`${Date.now()}-${file.originalname}`);
    },
});

// Complaint image upload: save to uploads/complaints
const complainStorage = multer.diskStorage({
    destination: function (req, file, cb) {
        const dir = path.join(__dirname, "uploads", "complaints");
        if (!fs.existsSync(dir)) {
            try {
                fs.mkdirSync(dir, { recursive: true });
            } catch (err) {
                console.warn("Could not create complaints directory. Expected on Vercel.");
            }
        }
        cb(null, dir);
    },
    filename: function (req, file, cb) {
        const ext = (path.extname(file.originalname) || "").toLowerCase() || ".jpg";
        cb(null, `${Date.now()}-complain${ext}`);
    },
});

const uploadFile = multer({ storage });
const uploadComplainImage = multer({
    storage: complainStorage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowed = /\.(jpe?g|png|gif|webp)$/i;
        if (allowed.test(file.originalname) || file.mimetype.startsWith("image/")) {
            cb(null, true);
        } else {
            cb(new Error("Only image files (JPEG, PNG, GIF, WebP) are allowed."), false);
        }
    },
});

module.exports = uploadFile;
module.exports.uploadComplainImage = uploadComplainImage;