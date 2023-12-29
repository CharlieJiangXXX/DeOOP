from model.llama import *
import fire


def main():
    llama = CodeLlama("/data/codellama/CodeLlama-34b-Instruct-hf/")
    # torchrun --nproc_per_node 4 cli_infer.py --ckpt_dir /data/codellama/CodeLlama-34b-Instruct/
    llama.rename("""
void __fastcall base64_encode(const char *in, size_t inlen, char *out, size_t outlen)
{
  size_t v4; // rax
  unsigned __int8 v5; // al
  const char *v6; // r9
  const char *v7; // r11
  const char *v8; // r10
  char *v9; // rbx
  char *v10; // rsi
  unsigned __int8 v11; // dl
  char v12; // dl
  unsigned __int8 v13; // al
  char v14; // al
  char *v15; // rdx
  const char *v16; // rsi
  unsigned __int8 v17; // al
  unsigned __int8 v18; // cl
  char v19; // al

  if ( (outlen & 3) == 0 && (v4 = 3 * (outlen >> 2), v4 == inlen) )
  {
    if ( v4 )
    {
      v16 = &in[v4];
      do
      {
        v17 = *in;
        out += 4;
        in += 3;
        *(out - 4) = b64c[v17 >> 2];
        v18 = *(in - 2);
        *(out - 3) = b64c[((v18 >> 4) + 16 * v17) & 0x3F];
        v19 = b64c[*(in - 1) & 0x3F];
        *(out - 2) = b64c[(((unsigned __int8)*(in - 1) >> 6) + 4 * v18) & 0x3F];
        *(out - 1) = v19;
      }
      while ( in != v16 );
    }
  }
  else if ( outlen )
  {
    if ( inlen )
    {
      v5 = *in;
      *out = b64c[((unsigned __int8)*in >> 2) & 0x3F];
      if ( outlen != 1 )
      {
        v6 = &in[inlen - 1];
        v7 = &in[inlen - 3];
        v8 = &in[inlen - 2];
        v9 = &out[outlen];
        v10 = out;
        while ( 1 )
        {
          v14 = 16 * v5;
          if ( v6 == in )
            break;
          v11 = in[1];
          v10[1] = b64c[((v11 >> 4) + v14) & 0x3F];
          if ( outlen == 2 )
            return;
          v12 = 4 * v11;
          if ( v8 == in )
          {
            v10[2] = b64c[v12 & 0x3C];
            if ( outlen == 3 )
              return;
LABEL_17:
            v10[3] = 61;
            v15 = v10 + 4;
            if ( outlen == 4 )
              return;
            goto LABEL_18;
          }
          v13 = in[2];
          v10[2] = b64c[((v13 >> 6) + v12) & 0x3F];
          if ( v9 - v10 == 3 )
            return;
          v10 += 4;
          *(v10 - 1) = b64c[v13 & 0x3F];
          if ( outlen == 4 )
            return;
          if ( v7 == in )
          {
            v15 = v10;
LABEL_18:
            *v15 = 0;
            return;
          }
          v5 = in[3];
          in += 3;
          *v10 = b64c[v5 >> 2];
          if ( outlen == 5 )
            return;
          outlen -= 4LL;
        }
        v10[1] = b64c[v14 & 0x30];
        if ( outlen != 2 )
        {
          v10[2] = 61;
          if ( outlen != 3 )
            goto LABEL_17;
        }
      }
    }
    else
    {
      *out = 0;
    }
  }
}
""", RenameMode.Reasoning)


if __name__ == '__main__':
    main()
