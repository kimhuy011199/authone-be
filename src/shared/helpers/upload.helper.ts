import cloudinary from '../../config/cloudinary.config';

const uploadImg = async (base64Img: string) => {
  const response = await cloudinary.uploader.upload(base64Img, {
    upload_preset: process.env.UPLOAD_PRESET,
  });

  return response.url;
};

const uploadHelper = {
  uploadImg,
};

export default uploadHelper;
