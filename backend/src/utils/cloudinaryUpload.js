import cloudinary from "../lib/cloudinary.js";

export function uploadBufferToCloudinary(buffer, { folder, resource_type }) {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      { folder, resource_type },
      (error, result) => {
        if (error) return reject(error);
        resolve(result);
      }
    );

    stream.end(buffer);
  });
}