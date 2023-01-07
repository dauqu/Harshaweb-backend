let uuidv4 = require('uuid');
let multer = require('multer');

var DIR = './medias_app/';
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, DIR);
    },
    filename: (req, file, cb) => {
        const fileName = file.originalname.toLowerCase().split(' ').join('-');
        cb(null, uuidv4.v4() + '-' + fileName)
    }
});
var upload = multer({
    storage: storage,
    fileFilter: (req, file, cb) => {
        if (file.mimetype == "image/png" || file.mimetype == "image/jpg" || file.mimetype == "image/jpeg" || file.mimetype == 'application/pdf' || file.mimetype == 'application/msword' || file.mimetype == 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' || file.mimetype == 'application/vnd.ms-excel' || file.mimetype == 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' || file.mimetype == 'application/vnd.ms-powerpoint' || file.mimetype == 'application/vnd.openxmlformats-officedocument.presentationml.presentation' || file.mimetype == 'text/plain') {
            cb(null, true);
        } else {
            cb(null, false);
            return cb(new Error('Only .png, .jpg , .jpeg and .pdf format allowed!'));
        }
    }
});

module.exports = upload;