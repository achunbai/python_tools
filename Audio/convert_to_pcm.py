import math
from pydub import AudioSegment
from pydub.utils import which

# If ffmpeg is not in the system PATH, specify the paths here
# AudioSegment.converter = which("path\\to\\ffmpeg.exe")
# AudioSegment.ffprobe = which("path\\to\\ffprobe.exe")

# Input and output file paths
input_mp3 = "input.mp3"
output_pcm = "output.pcm"
output_wav = "output.wav"

# Audio parameters
sample_rate = 44100  # 44.1kHz
bit_depth = 16       # 16-bit
channels = 2         # Stereo

# Target file size in bytes
target_size = 2.5 * 1024 * 1024  # 2.5MB

# Calculate bytes per second
bytes_per_second = sample_rate * channels * (bit_depth // 8)

# Calculate required duration in seconds
max_duration_sec = target_size / bytes_per_second

# Convert to milliseconds
max_duration_ms = math.floor(max_duration_sec * 1000)

# Load MP3 file
audio = AudioSegment.from_mp3(input_mp3)

# Convert audio parameters
audio = audio.set_frame_rate(sample_rate).set_sample_width(bit_depth // 8).set_channels(channels)

# Trim audio
audio = audio[:max_duration_ms]

# Export as raw PCM
audio.export(output_pcm, format="raw")

# Export as WAV format
audio.export(output_wav, format="wav")

print(f"Conversion completed: {output_pcm} and {output_wav}")