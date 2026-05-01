using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

namespace ShadingThePhantom
{
    public partial class Form1 : Form
    {
        private string hPath = "";
        private string ePath = "";
        private const string SIG          = "PH_V1";
        private const float  ENT_THRESHOLD = 0.5f;
        private const int    PBKDF2_ITER   = 600_000;
        private const int    SALT_SIZE     = 16;
        private const int    NONCE_SIZE    = 12;
        private const int    TAG_SIZE      = 16;

        private TextBox    tMsg1 = null!, tPass1 = null!, tMsg2 = null!, tPass2 = null!;
        private TextBox    tDecodePass = null!, tResult = null!;
        private Label      l2 = null!, lPass2 = null!, lMsg1Label = null!;
        private CheckBox   chkDual = null!;
        private PictureBox pH = null!, pE = null!;

        private Button bLoadEncode = null!;
        private Button bLoadDecode = null!;

        public Form1()
        {
            SetupUI();
            this.Text          = "Shading the Phantom  |  Forensic Dual-Layer Steganography";
            this.MinimumSize   = new Size(660, 700);
            this.Size          = new Size(800, 860);
            this.StartPosition = FormStartPosition.CenterScreen;
        }

        private void InitializeComponent() { }

        // ═══════════════════════════════════════════════════
        //  ECC — HAMMING (7,4)
        // ═══════════════════════════════════════════════════
        private byte[] ApplyHamming(byte[] data)
        {
            var bits = new List<int>();
            foreach (var b in data)
                for (int i = 7; i >= 0; i--) bits.Add((b >> i) & 1);

            var res = new List<int>();
            for (int i = 0; i < bits.Count; i += 4)
            {
                int[] d = new int[4];
                for (int j = 0; j < 4 && (i + j) < bits.Count; j++) d[j] = bits[i + j];
                int p1 = d[0] ^ d[1] ^ d[3];
                int p2 = d[0] ^ d[2] ^ d[3];
                int p3 = d[1] ^ d[2] ^ d[3];
                res.AddRange(new[] { p1, p2, d[0], p3, d[1], d[2], d[3] });
            }
            byte[] outB = new byte[(res.Count + 7) / 8];
            for (int i = 0; i < res.Count; i++)
                outB[i / 8] |= (byte)(res[i] << (7 - (i % 8)));
            return outB;
        }

        private byte[] DecodeHamming(byte[] data)
        {
            var bits = new List<int>();
            foreach (var b in data)
                for (int i = 7; i >= 0; i--) bits.Add((b >> i) & 1);

            var res = new List<int>();
            for (int i = 0; i + 6 < bits.Count; i += 7)
            {
                int[] h = new int[7];
                for (int j = 0; j < 7; j++) h[j] = bits[i + j];
                int s1  = h[0] ^ h[2] ^ h[4] ^ h[6];
                int s2  = h[1] ^ h[2] ^ h[5] ^ h[6];
                int s3  = h[3] ^ h[4] ^ h[5] ^ h[6];
                int err = s1 + (s2 * 2) + (s3 * 4);
                if (err > 0 && err <= 7) h[err - 1] ^= 1;
                res.AddRange(new[] { h[2], h[4], h[5], h[6] });
            }
            byte[] outB = new byte[res.Count / 8];
            for (int i = 0; i < outB.Length * 8; i++)
                outB[i / 8] |= (byte)(res[i] << (7 - (i % 8)));
            return outB;
        }

        // ═══════════════════════════════════════════════════
        //  COMPRESSION
        // ═══════════════════════════════════════════════════
        private byte[] Compress(byte[] d)
        {
            using var ms = new MemoryStream();
            using (var g = new GZipStream(ms, CompressionMode.Compress)) g.Write(d, 0, d.Length);
            return ms.ToArray();
        }

        private byte[]? Decompress(byte[] d)
        {
            try
            {
                using var ms = new MemoryStream(d);
                using var g  = new GZipStream(ms, CompressionMode.Decompress);
                using var r  = new MemoryStream();
                g.CopyTo(r);
                return r.ToArray();
            }
            catch { return null; }
        }

        // ═══════════════════════════════════════════════════
        //  PBKDF2 KEY DERIVATION + AES-256-GCM
        // ═══════════════════════════════════════════════════
        private byte[] DeriveKey(string password, byte[] salt)
        {
            using var kdf = new Rfc2898DeriveBytes(
                password, salt, PBKDF2_ITER, HashAlgorithmName.SHA256);
            return kdf.GetBytes(32);
        }

        private byte[]? AESEncrypt(byte[] data, string password)
        {
            try
            {
                byte[] salt  = RandomNumberGenerator.GetBytes(SALT_SIZE);
                byte[] nonce = RandomNumberGenerator.GetBytes(NONCE_SIZE);
                byte[] key   = DeriveKey(password, salt);

                byte[] ciphertext = new byte[data.Length];
                byte[] tag        = new byte[TAG_SIZE];

                using var gcm = new AesGcm(key, TAG_SIZE);
                gcm.Encrypt(nonce, data, ciphertext, tag);

                byte[] output = new byte[SALT_SIZE + NONCE_SIZE + TAG_SIZE + ciphertext.Length];
                int pos = 0;
                Buffer.BlockCopy(salt,       0, output, pos, SALT_SIZE);  pos += SALT_SIZE;
                Buffer.BlockCopy(nonce,      0, output, pos, NONCE_SIZE); pos += NONCE_SIZE;
                Buffer.BlockCopy(tag,        0, output, pos, TAG_SIZE);   pos += TAG_SIZE;
                Buffer.BlockCopy(ciphertext, 0, output, pos, ciphertext.Length);
                return output;
            }
            catch { return null; }
        }

        private byte[]? AESDecrypt(byte[] data, string password)
        {
            try
            {
                int minLen = SALT_SIZE + NONCE_SIZE + TAG_SIZE;
                if (data.Length <= minLen) return null;

                byte[] salt       = new byte[SALT_SIZE];
                byte[] nonce      = new byte[NONCE_SIZE];
                byte[] tag        = new byte[TAG_SIZE];
                byte[] ciphertext = new byte[data.Length - minLen];

                int pos = 0;
                Buffer.BlockCopy(data, pos, salt,       0, SALT_SIZE);  pos += SALT_SIZE;
                Buffer.BlockCopy(data, pos, nonce,      0, NONCE_SIZE); pos += NONCE_SIZE;
                Buffer.BlockCopy(data, pos, tag,        0, TAG_SIZE);   pos += TAG_SIZE;
                Buffer.BlockCopy(data, pos, ciphertext, 0, ciphertext.Length);

                byte[] key       = DeriveKey(password, salt);
                byte[] plaintext = new byte[ciphertext.Length];

                using var gcm = new AesGcm(key, TAG_SIZE);
                gcm.Decrypt(nonce, ciphertext, tag, plaintext);
                return plaintext;
            }
            catch { return null; }
        }

        // ═══════════════════════════════════════════════════
        //  ENTROPY ANALYSIS
        // ═══════════════════════════════════════════════════
        private float GetStableEntropy(byte[] px, int offset)
        {
            int limit = Math.Min(64, px.Length - offset);
            if (limit < 64) return 0f;
            int[] counts = new int[64];
            for (int i = 0; i < limit; i++) counts[(px[offset + i] >> 2) & 0x3F]++;
            float ent = 0f;
            foreach (int c in counts)
                if (c > 0) { float prob = (float)c / limit; ent -= prob * (float)Math.Log2(prob); }
            return ent;
        }

        // ═══════════════════════════════════════════════════
        //  SALTED BLOCK OFFSET
        // ═══════════════════════════════════════════════════
        private int DeriveBlockOffset(string password, byte[] px, int totalBlocks)
        {
            if (totalBlocks <= 1) return 0;
            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(password));
            byte[] hash    = hmac.ComputeHash(Encoding.UTF8.GetBytes("stego_offset"));
            uint   raw     = BitConverter.ToUInt32(hash, 0);
            int    maxSkip = Math.Max(1, totalBlocks / 4);
            return (int)(raw % (uint)maxSkip);
        }

        // ═══════════════════════════════════════════════════
        //  ENCODE
        // ═══════════════════════════════════════════════════
        private void RunHide()
        {
            if (string.IsNullOrEmpty(hPath))           { MessageBox.Show("Please load a host image first.");      return; }
            if (tPass1.Text.Length < 8)                 { MessageBox.Show("Primary password must be >= 8 chars."); return; }
            if (string.IsNullOrWhiteSpace(tMsg1.Text))  { MessageBox.Show("Primary message cannot be empty.");    return; }
            if (chkDual.Checked)
            {
                if (string.IsNullOrWhiteSpace(tMsg2.Text)) { MessageBox.Show("Decoy message cannot be empty.");    return; }
                if (tPass2.Text.Length < 8)                 { MessageBox.Show("Decoy password must be >= 8 chars."); return; }
                if (tPass1.Text == tPass2.Text)
                {
                    MessageBox.Show(
                        "Both layers have the same password.\n\n" +
                        "Please use a different password for each layer.\n" +
                        "The whole point of dual-layer is that each password reveals a different message.",
                        "Passwords Must Differ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    tPass2.Focus();
                    return;
                }
            }

            using var sfd = new SaveFileDialog { Filter = "PNG Image|*.png", Title = "Save stego image" };
            if (sfd.ShowDialog() != DialogResult.OK) return;

            try
            {
                using Bitmap bmp = LoadBitmapSafe(hPath)
                    ?? throw new Exception("File is damaged or not a valid image.");

                BitmapData bd = bmp.LockBits(
                    new Rectangle(0, 0, bmp.Width, bmp.Height),
                    ImageLockMode.ReadWrite, PixelFormat.Format24bppRgb);
                byte[] px = new byte[Math.Abs(bd.Stride) * bmp.Height];
                Marshal.Copy(bd.Scan0, px, 0, px.Length);

                byte[] enc1  = AESEncrypt(Compress(Encoding.UTF8.GetBytes(SIG + "|" + tMsg1.Text)), tPass1.Text)
                               ?? throw new Exception("Encryption failed.");
                byte[] prot1 = ApplyHamming(enc1);
                byte[] f1    = BitConverter.GetBytes(prot1.Length).Concat(prot1).ToArray();

                byte[]? f2 = null;
                if (chkDual.Checked)
                {
                    byte[] enc2  = AESEncrypt(Compress(Encoding.UTF8.GetBytes(SIG + "|" + tMsg2.Text)), tPass2.Text)
                                   ?? throw new Exception("Encryption failed for decoy.");
                    byte[] prot2 = ApplyHamming(enc2);
                    f2           = BitConverter.GetBytes(prot2.Length).Concat(prot2).ToArray();
                }

                var blocks = new List<int>();
                for (int i = 0; i < px.Length - 64; i += 64)
                    if (GetStableEntropy(px, i) > ENT_THRESHOLD) blocks.Add(i);

                int skip1         = DeriveBlockOffset(tPass1.Text, px, blocks.Count);
                int usableAfterS1 = (blocks.Count - skip1) * 64;
                if (f1.Length * 8 > usableAfterS1)
                {
                    bmp.UnlockBits(bd);
                    MessageBox.Show(
                        $"Image too small for the primary message.\n" +
                        $"Available: {usableAfterS1 / 8} bytes  |  Needed: {f1.Length} bytes\n\n" +
                        "Use a larger or more detailed image.");
                    return;
                }

                byte[] noiseBuf = new byte[blocks.Count * 64];
                RandomNumberGenerator.Fill(noiseBuf);
                for (int idx = 0; idx < blocks.Count; idx++)
                    for (int j = 0; j < 64; j++)
                        px[blocks[idx] + j] = (byte)(
                            (px[blocks[idx] + j] & 0xFD) | ((noiseBuf[idx * 64 + j] & 1) << 1));

                int i1 = 0;
                for (int b = skip1; b < blocks.Count && i1 < f1.Length * 8; b++)
                    for (int j = 0; j < 64 && i1 < f1.Length * 8; j++)
                    {
                        int bit = (f1[i1 / 8] >> (7 - (i1 % 8))) & 1;
                        px[blocks[b] + j] = (byte)((px[blocks[b] + j] & 0xFE) | bit);
                        i1++;
                    }

                if (f2 != null)
                {
                    int skip2 = DeriveBlockOffset(tPass2.Text, px, blocks.Count);
                    int i2    = 0;
                    for (int b = skip2; b < blocks.Count && i2 < f2.Length * 8; b++)
                        for (int j = 0; j < 64 && i2 < f2.Length * 8; j++)
                        {
                            int bit = (f2[i2 / 8] >> (7 - (i2 % 8))) & 1;
                            px[blocks[b] + j] = (byte)((px[blocks[b] + j] & 0xFD) | (bit << 1));
                            i2++;
                        }
                }

                Marshal.Copy(px, 0, bd.Scan0, px.Length);
                bmp.UnlockBits(bd);
                bmp.Save(sfd.FileName, ImageFormat.Png);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Encoding error:\n" + ex.Message);
                return;
            }

            CleanEncodeMemory();
            MessageBox.Show("Encoding successful.", "Done");
        }

        // ═══════════════════════════════════════════════════
        //  DECODE
        // ═══════════════════════════════════════════════════
        private void RunReveal()
        {
            if (string.IsNullOrEmpty(ePath))           { MessageBox.Show("Please open a stego PNG first."); return; }
            if (string.IsNullOrEmpty(tDecodePass.Text)) { MessageBox.Show("Enter the password.");           return; }

            try
            {
                using Bitmap bmp = LoadBitmapSafe(ePath)
                    ?? throw new Exception("File is damaged or not a valid PNG.");

                BitmapData bd = bmp.LockBits(
                    new Rectangle(0, 0, bmp.Width, bmp.Height),
                    ImageLockMode.ReadOnly, PixelFormat.Format24bppRgb);
                byte[] px = new byte[Math.Abs(bd.Stride) * bmp.Height];
                Marshal.Copy(bd.Scan0, px, 0, px.Length);
                bmp.UnlockBits(bd);

                var blocks = new List<int>();
                for (int i = 0; i < px.Length - 64; i += 64)
                    if (GetStableEntropy(px, i) > ENT_THRESHOLD) blocks.Add(i);

                int skip = DeriveBlockOffset(tDecodePass.Text, px, blocks.Count);

                var b1 = new List<byte>();
                var b2 = new List<byte>();
                for (int b = skip; b < blocks.Count; b++)
                    for (int j = 0; j < 64; j++)
                    {
                        b1.Add((byte)( px[blocks[b] + j]       & 1));
                        b2.Add((byte)((px[blocks[b] + j] >> 1) & 1));
                    }

                if (TryDecrypt(b1.ToArray(), tDecodePass.Text)) return;
                if (TryDecrypt(b2.ToArray(), tDecodePass.Text)) return;

                tResult.Text = "Decryption failed: wrong password or no hidden data.";
            }
            catch (Exception ex)
            {
                tResult.Text = "Error: " + ex.Message;
            }
        }

        private bool TryDecrypt(byte[] bits, string pass)
        {
            if (bits.Length < 40) return false;

            byte[] raw = new byte[bits.Length / 8];
            for (int i = 0; i < raw.Length; i++)
                for (int j = 0; j < 8; j++)
                    raw[i] |= (byte)(bits[i * 8 + j] << (7 - j));

            if (raw.Length < 4) return false;
            int len = BitConverter.ToInt32(raw, 0);
            if (len <= 0 || len > raw.Length - 4) return false;

            byte[] payload  = new byte[len];
            Array.Copy(raw, 4, payload, 0, len);

            byte[]? corrected = DecodeHamming(payload);
            byte[]? dec       = AESDecrypt(corrected, pass);
            if (dec == null) return false;

            byte[]? decomp = Decompress(dec);
            if (decomp == null) return false;

            string s = Encoding.UTF8.GetString(decomp);
            if (s.StartsWith(SIG + "|"))
            {
                tResult.Text = "[DECRYPTED]:\n" + s[(SIG.Length + 1)..];
                return true;
            }
            return false;
        }

        // ═══════════════════════════════════════════════════
        //  HELPERS
        // ═══════════════════════════════════════════════════
        private static Bitmap? LoadBitmapSafe(string path)
        {
            try
            {
                using var fs  = new FileStream(path, FileMode.Open, FileAccess.Read);
                using var tmp = Image.FromStream(fs, false, true);
                return new Bitmap(tmp);
            }
            catch { return null; }
        }

        private void CleanEncodeMemory()
        {
            if (pH.Image != null) { pH.Image.Dispose(); pH.Image = null; }
            hPath = "";
            tMsg1.Clear(); tPass1.Clear();
            tMsg2.Clear(); tPass2.Clear();
            bLoadEncode.Text = "📂  LOAD IMAGE";
        }

        private void CleanDecodeMemory()
        {
            if (pE.Image != null) { pE.Image.Dispose(); pE.Image = null; }
            ePath = "";
            tDecodePass.Clear();
            tResult.Clear();
            bLoadDecode.Text = "📂  OPEN PNG";
        }

        // ═══════════════════════════════════════════════════
        //  UI
        // ═══════════════════════════════════════════════════
        private void SetupUI()
        {
            this.BackColor = Color.FromArgb(25, 25, 30);
            Color blue  = Color.DodgerBlue;
            Color dark  = Color.FromArgb(40, 40, 45);
            Color btnBg = Color.FromArgb(60, 60, 70);
            Color input = Color.FromArgb(55, 55, 60);

            var tc = new TabControl { Dock = DockStyle.Fill, Padding = new Point(12, 5) };
            var p1 = new TabPage("  ENCODE  ")      { BackColor = dark, Padding = new Padding(12) };
            var p2 = new TabPage("  DECODE  ")      { BackColor = dark, Padding = new Padding(12) };
            var p3 = new TabPage("  HOW TO USE  ")  { BackColor = dark, Padding = new Padding(12) };

            BuildEncodeTab(p1, blue, btnBg, input);
            BuildDecodeTab(p2, blue, btnBg, input);
            BuildHelpTab(p3, blue);

            tc.TabPages.AddRange(new[] { p1, p2, p3 });
            this.Controls.Add(tc);
        }

        // ── ENCODE TAB ───────────────────────────────────
        private void BuildEncodeTab(TabPage p, Color blue, Color btnBg, Color input)
        {
            var tbl = new TableLayoutPanel
            {
                Dock        = DockStyle.Fill,
                ColumnCount = 2,
                RowCount    = 11,
                BackColor   = Color.Transparent
            };
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 62f));
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 38f));

            int[] rowH = { 42, 28, 80, 14, 34, 14, 28, 80, 14, 52, 0 };
            foreach (int h in rowH)
                tbl.RowStyles.Add(new RowStyle(
                    h == 0 ? SizeType.Percent : SizeType.Absolute,
                    h == 0 ? 100f : h));

            // Row 0 — load button (spans both columns)
            bLoadEncode = MakeButton("📂  LOAD IMAGE", btnBg);
            bLoadEncode.Dock = DockStyle.Fill;
            bLoadEncode.Click += (s, e) =>
            {
                using var o = new OpenFileDialog
                    { Filter = "Image files|*.png;*.bmp;*.jpg;*.jpeg" };
                if (o.ShowDialog() != DialogResult.OK) return;
                var bmp = LoadBitmapSafe(o.FileName);
                if (bmp == null) { MessageBox.Show("File is damaged or not a valid image."); return; }
                hPath = o.FileName;
                if (pH.Image != null) pH.Image.Dispose();
                pH.Image = bmp;

                BitmapData bd = bmp.LockBits(
                    new Rectangle(0, 0, bmp.Width, bmp.Height),
                    ImageLockMode.ReadOnly, PixelFormat.Format24bppRgb);
                byte[] px = new byte[Math.Abs(bd.Stride) * bmp.Height];
                Marshal.Copy(bd.Scan0, px, 0, px.Length);
                bmp.UnlockBits(bd);
                int cap = 0;
                for (int i = 0; i < px.Length - 64; i += 64)
                    if (GetStableEntropy(px, i) > ENT_THRESHOLD) cap += 64;
                bLoadEncode.Text = $"📂  {Path.GetFileName(o.FileName)}   (~{cap / 8 / 7} chars usable)";
            };
            tbl.Controls.Add(bLoadEncode, 0, 0);
            tbl.SetColumnSpan(bLoadEncode, 2);

            // Row 1 — Layer 1 column headers
            lMsg1Label = MakeLabel("Secret message:", blue);
            tbl.Controls.Add(lMsg1Label, 0, 1);
            tbl.Controls.Add(MakeLabel("Password (>= 8 chars):", blue), 1, 1);

            // Row 2 — Layer 1 message + password fields
            tMsg1  = MakeMultiBox(input, blue, "Type your secret message here...");
            tPass1 = MakeSingleBox(input, blue, "Password", password: true);
            tbl.Controls.Add(tMsg1,  0, 2);
            tbl.Controls.Add(tPass1, 1, 2);

            // Row 3 — spacer
            tbl.Controls.Add(new Label { BackColor = Color.Transparent }, 0, 3);

            // Row 4 — dual-layer checkbox
            chkDual = new CheckBox
            {
                Text      = "Enable Dual-Layer  ",
                Dock      = DockStyle.Fill,
                ForeColor = blue,
                Font      = new Font("Segoe UI", 9, FontStyle.Bold),
                BackColor = Color.Transparent
            };
            tbl.Controls.Add(chkDual, 0, 4);
            tbl.SetColumnSpan(chkDual, 2);

            // Row 5 — spacer between checkbox and Layer 2 labels
            tbl.Controls.Add(new Label { BackColor = Color.Transparent }, 0, 5);

            // Row 6 — Layer 2 column headers (hidden by default)
            l2     = MakeLabel("Decoy message:", blue);
            lPass2 = MakeLabel("Decoy password (>= 8 chars):", blue);
            l2.Visible = lPass2.Visible = false;
            tbl.Controls.Add(l2,     0, 6);
            tbl.Controls.Add(lPass2, 1, 6);

            // Row 7 — Layer 2 fields (hidden by default)
            tMsg2  = MakeMultiBox(input, blue, "Type your decoy message here...");
            tPass2 = MakeSingleBox(input, blue, "Decoy password", password: true);
            tMsg2.Visible = tPass2.Visible = false;
            tbl.Controls.Add(tMsg2,  0, 7);
            tbl.Controls.Add(tPass2, 1, 7);

            // Row 8 — spacer before encode button
            tbl.Controls.Add(new Label { BackColor = Color.Transparent }, 0, 8);

            // Toggle visibility + rename label
            chkDual.CheckedChanged += (s, e) =>
            {
                bool on = chkDual.Checked;
                l2.Visible = lPass2.Visible = tMsg2.Visible = tPass2.Visible = on;
                lMsg1Label.Text = on ? "Primary (real) message:" : "Secret message:";
            };

            // Row 9 — encode button
            var bH = MakeButton("🔒  EXECUTE SHIELDING", blue);
            bH.Dock      = DockStyle.Fill;
            bH.Font      = new Font("Segoe UI", 10, FontStyle.Bold);
            bH.ForeColor = Color.White;
            bH.Click    += (s, e) => RunHide();
            tbl.Controls.Add(bH, 0, 9);
            tbl.SetColumnSpan(bH, 2);

            // Row 10 — image preview (fills remaining vertical space)
            pH = new PictureBox
            {
                Dock        = DockStyle.Fill,
                SizeMode    = PictureBoxSizeMode.Zoom,
                BorderStyle = BorderStyle.FixedSingle,
                BackColor   = Color.Black
            };
            tbl.Controls.Add(pH, 0, 10);
            tbl.SetColumnSpan(pH, 2);

            p.Controls.Add(tbl);
        }

        // ── DECODE TAB ───────────────────────────────────
        private void BuildDecodeTab(TabPage p, Color blue, Color btnBg, Color input)
        {
            var tbl = new TableLayoutPanel
            {
                Dock        = DockStyle.Fill,
                ColumnCount = 1,
                RowCount    = 10,
                BackColor   = Color.Transparent
            };
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));

            int[] rowH = { 42, 14, 28, 34, 52, 14, 28, 110, 42, 0 };
            foreach (int h in rowH)
                tbl.RowStyles.Add(new RowStyle(
                    h == 0 ? SizeType.Percent : SizeType.Absolute,
                    h == 0 ? 100f : h));

            // Row 0 — open button
            bLoadDecode = MakeButton("📂  OPEN PNG", btnBg);
            bLoadDecode.Dock = DockStyle.Fill;
            bLoadDecode.Click += (s, e) =>
            {
                using var o = new OpenFileDialog { Filter = "PNG Image|*.png" };
                if (o.ShowDialog() != DialogResult.OK) return;
                var bmp = LoadBitmapSafe(o.FileName);
                if (bmp == null) { MessageBox.Show("File is damaged or not a valid PNG."); return; }
                ePath = o.FileName;
                if (pE.Image != null) pE.Image.Dispose();
                pE.Image = bmp;
                bLoadDecode.Text = "📂  " + Path.GetFileName(o.FileName);
            };
            tbl.Controls.Add(bLoadDecode, 0, 0);

            // Row 1 — spacer
            tbl.Controls.Add(new Label { BackColor = Color.Transparent }, 0, 1);

            // Row 2 — password label
            tbl.Controls.Add(MakeLabel("Password:", blue), 0, 2);

            // Row 3 — password field
            tDecodePass = MakeSingleBox(input, blue, "Enter password...", password: true);
            tbl.Controls.Add(tDecodePass, 0, 3);

            // Row 4 — reveal button
            var bR = MakeButton("🔓  REVEAL DATA", blue);
            bR.Dock      = DockStyle.Fill;
            bR.Font      = new Font("Segoe UI", 10, FontStyle.Bold);
            bR.ForeColor = Color.White;
            bR.Click    += (s, e) => RunReveal();
            tbl.Controls.Add(bR, 0, 4);

            // Row 5 — spacer
            tbl.Controls.Add(new Label { BackColor = Color.Transparent }, 0, 5);

            // Row 6 — result label
            tbl.Controls.Add(MakeLabel("Result:", blue), 0, 6);

            // Row 7 — result text box
            tResult = new TextBox
            {
                Dock       = DockStyle.Fill,
                Multiline  = true, ReadOnly = true,
                BackColor  = Color.Black, ForeColor = blue,
                Font       = new Font("Consolas", 10),
                ScrollBars = ScrollBars.Vertical
            };
            tbl.Controls.Add(tResult, 0, 7);

            // Row 8 — clear button
            var bClear = MakeButton("🗑  CLEAR", Color.FromArgb(80, 30, 30));
            bClear.Dock  = DockStyle.Fill;
            bClear.Click += (s, e) => CleanDecodeMemory();
            tbl.Controls.Add(bClear, 0, 8);

            // Row 9 — image preview (fills remaining vertical space)
            pE = new PictureBox
            {
                Dock        = DockStyle.Fill,
                SizeMode    = PictureBoxSizeMode.Zoom,
                BorderStyle = BorderStyle.FixedSingle,
                BackColor   = Color.Black
            };
            tbl.Controls.Add(pE, 0, 9);

            p.Controls.Add(tbl);
        }

        // ── HOW TO USE TAB ───────────────────────────────
        private void BuildHelpTab(TabPage p, Color blue)
        {
            var rtb = new RichTextBox
            {
                Dock        = DockStyle.Fill,
                ReadOnly    = true,
                BackColor   = Color.FromArgb(30, 30, 35),
                ForeColor   = Color.White,
                Font        = new Font("Segoe UI", 10),
                BorderStyle = BorderStyle.None,
                ScrollBars  = RichTextBoxScrollBars.Vertical
            };

            void Header(string t) { rtb.SelectionColor = blue;                              rtb.AppendText(t + "\n"); }
            void Body(string t)   { rtb.SelectionColor = Color.White;                       rtb.AppendText(t); }
            void Warn(string t)   { rtb.SelectionColor = Color.FromArgb(255, 120, 120);     rtb.AppendText(t); }
            void Grey(string t)   { rtb.SelectionColor = Color.FromArgb(170, 170, 170);     rtb.AppendText(t); }

            rtb.SelectionFont  = new Font("Segoe UI", 13, FontStyle.Bold);
            rtb.SelectionColor = blue;
            rtb.AppendText("SHADING THE PHANTOM — USER GUIDE\n");
            rtb.SelectionFont  = new Font("Segoe UI", 10);
            Body("══════════════════════════════════════════════\n\n");

            Header("▶  HIDING A MESSAGE  (Encode tab)\n");
            Body(
                "  1.  Click LOAD IMAGE and choose any PNG, JPG, or BMP.\n" +
                "      Detailed photos and textures hold significantly more data\n" +
                "      than plain or solid-colour images.\n" +
                "      The button shows an estimated character capacity after loading.\n\n" +
                "  2.  Type or paste your secret message. Any length is supported.\n\n" +
                "  3.  Enter a password of at least 8 characters.\n" +
                "      The password is never saved anywhere — do not lose it.\n\n" +
                "  4.  (Optional) Check 'Enable Dual-Layer' to add a decoy message.\n" +
                "      Use a completely different password for each layer.\n" +
                "      If you are ever forced to reveal a password, give the decoy one.\n\n" +
                "  5.  Click EXECUTE SHIELDING and save the output as PNG.\n\n");

            Header("▶  RECOVERING A MESSAGE  (Decode tab)\n");
            Body(
                "  1.  Click OPEN PNG and select your stego image.\n\n" +
                "  2.  Type the password you used during encoding.\n\n" +
                "  3.  Click REVEAL DATA. The decrypted message appears below.\n\n" +
                "  4.  Click CLEAR when done to wipe the image and result from the screen.\n\n");

            Header("▶  CRITICAL WARNINGS\n");
            Warn(
                "  ⚠  Never share stego images through platforms that recompress images.\n" +
                "     WhatsApp, Viber, Instagram, and Telegram (default) all recompress\n" +
                "     to JPEG, which permanently destroys the hidden data.\n\n" +
                "  ⚠  Use Telegram → 'Send as File' or email as an attachment.\n" +
                "     The PNG must arrive byte-for-byte identical to what was saved.\n\n" +
                "  ⚠  If you lose the password, the message is irrecoverable.\n\n");

            Header("▶  HOW IT WORKS\n");
            Grey(
                "  Text → GZip compress → AES-256-GCM encrypt (PBKDF2, 600 000 iterations,\n" +
                "  unique 16-byte salt + 12-byte nonce per message, 16-byte auth tag) →\n" +
                "  Hamming(7,4) error correction → embedded into the least-significant\n" +
                "  bit (bit-0) of pixels in high-entropy regions only, starting at a\n" +
                "  password-derived offset.\n\n" +
                "  AES-GCM is authenticated encryption: any tampering with the stored\n" +
                "  image that corrupts the ciphertext produces a clean decryption failure\n" +
                "  rather than silently garbled output.\n\n" +
                "  Dual-layer stores a second message in bit-1 of the same pixels.\n" +
                "  All unused bit-1 positions are filled with cryptographic random noise,\n" +
                "  making it impossible to prove whether a second layer exists.\n\n" +
                "  A one-bit change per pixel channel is below the threshold of human\n" +
                "  perception and most steganalysis tools.\n");

            p.Controls.Add(rtb);
        }

        // ── WIDGET FACTORIES ─────────────────────────────
        private static Button MakeButton(string text, Color bg) => new Button
        {
            Text      = text,
            FlatStyle = FlatStyle.Flat,
            BackColor = bg,
            ForeColor = Color.White,
            Font      = new Font("Segoe UI", 9, FontStyle.Bold),
            Margin    = new Padding(0, 0, 0, 4)
        };

        private static Label MakeLabel(string text, Color color) => new Label
        {
            Text      = text,
            AutoSize  = true,
            ForeColor = color,
            Font      = new Font("Segoe UI", 9),
            Dock      = DockStyle.Fill,
            BackColor = Color.Transparent
        };

        private static TextBox MakeMultiBox(Color bg, Color fg, string placeholder) => new TextBox
        {
            Dock            = DockStyle.Fill,
            Multiline       = true,
            ScrollBars      = ScrollBars.Vertical,
            AcceptsReturn   = true,
            BackColor       = bg,
            ForeColor       = fg,
            PlaceholderText = placeholder,
            Margin          = new Padding(0, 0, 4, 0)
        };

        private static TextBox MakeSingleBox(Color bg, Color fg, string placeholder, bool password = false)
        {
            var t = new TextBox
            {
                Dock            = DockStyle.Fill,
                BackColor       = bg,
                ForeColor       = fg,
                PlaceholderText = placeholder,
                Margin          = new Padding(4, 0, 0, 0)
            };
            if (password) t.PasswordChar = '●';
            return t;
        }
    }
}