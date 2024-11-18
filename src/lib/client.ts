import { MUTE } from "@/config/app";
import "client-only";
import { toast, type TypeOptions } from "react-toastify";

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0)).buffer;
}

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function alert(message: string, type: BasicColors) {
  let toastType: TypeOptions;
  if (type === "danger") {
    toastType = "error";
  } else {
    toastType = type;
  }
  toast(message, {
    type: toastType,
    onOpen: async () => {
      try {
        if (MUTE) {
          throw new Error("Muted");
        }
        const audio = new Audio(`/sounds/${type}.ogg`);
        audio.volume = 0.8;
        await audio.play();
      } catch (error) {
        console.warn("Audio will be played in your device.");
      }
    },
  });
}

export { base64ToArrayBuffer, arrayBufferToBase64, alert };
