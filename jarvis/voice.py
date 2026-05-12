"""
J.A.R.V.I.S. Voice Module
Speech recognition (input) + Text-to-speech (output)
"""

import threading


class VoiceModule:
    """Voice I/O for JARVIS — mic input via SpeechRecognition, TTS via pyttsx3."""

    def __init__(self):
        try:
            import speech_recognition as sr
            self._sr = sr
            self.recognizer = sr.Recognizer()
            self.recognizer.energy_threshold = 3000
            self.recognizer.dynamic_energy_threshold = True
        except ImportError as e:
            raise ImportError(f"speech_recognition not installed: {e}")

        try:
            import pyttsx3
            self.engine = pyttsx3.init()
            self._configure_tts()
        except ImportError as e:
            raise ImportError(f"pyttsx3 not installed: {e}")
        except Exception as e:
            raise RuntimeError(f"TTS engine failed to initialise: {e}")

        self._tts_lock = threading.Lock()

    def _configure_tts(self):
        """Configure TTS to sound like JARVIS — British male, measured pace."""
        voices = self.engine.getProperty("voices")
        preferred = None
        for v in voices:
            name = v.name.lower()
            if any(k in name for k in ("english", "en_gb", "british", "daniel", "alex")):
                preferred = v.id
                break
        if preferred:
            self.engine.setProperty("voice", preferred)
        self.engine.setProperty("rate", 165)
        self.engine.setProperty("volume", 0.95)

    def listen(self, timeout: int = 7, phrase_limit: int = 30) -> str:
        """
        Listen for a voice command and return recognised text.
        Returns an empty string on failure or silence.
        """
        sr = self._sr
        try:
            with sr.Microphone() as source:
                self.recognizer.adjust_for_ambient_noise(source, duration=0.5)
                audio = self.recognizer.listen(
                    source, timeout=timeout, phrase_time_limit=phrase_limit
                )
            text = self.recognizer.recognize_google(audio)
            return text.strip()
        except sr.WaitTimeoutError:
            return ""
        except sr.UnknownValueError:
            return ""
        except sr.RequestError as e:
            raise RuntimeError(f"Speech recognition service unavailable: {e}")

    def speak(self, text: str):
        """Speak text aloud.  Thread-safe — blocks until speech completes."""
        clean = _strip_markup(text)
        if not clean.strip():
            return
        with self._tts_lock:
            self.engine.say(clean)
            self.engine.runAndWait()

    def stop(self):
        """Stop any ongoing speech immediately."""
        try:
            self.engine.stop()
        except Exception:
            pass


def _strip_markup(text: str) -> str:
    """Remove Markdown code fences, headers, and Rich markup from TTS input."""
    import re
    text = re.sub(r"```[\s\S]*?```", "", text)
    text = re.sub(r"`[^`]+`", "", text)
    text = re.sub(r"\[.*?\]", "", text)
    text = re.sub(r"#{1,6}\s*", "", text)
    text = re.sub(r"\*{1,3}(.*?)\*{1,3}", r"\1", text)
    text = re.sub(r"\n{2,}", " ", text)
    return text.strip()
