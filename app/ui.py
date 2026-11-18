import streamlit as st
from app.router import run_codewarden, get_local_git_diff

st.set_page_config(page_title="CodeWarden | Local AI Security Auditor", page_icon="🛡️", layout="wide")

st.title("🛡️ CodeWarden: Offline PR Security & Architecture Auditor")
st.caption("100% Local Inference via Ollama (`codewarden:7b`) • Zero Cloud Uploads")

with st.sidebar:
    st.header("Audit Controls")
    uploaded_file = st.file_uploader(
        "Upload Source File or .diff/.patch",
        type=["py", "js", "jsx", "ts", "tsx", "java", "go", "cpp", "php", "cs", "diff", "patch"],
    )
    force_audit = st.checkbox("Force Strict Audit Mode", value=False)
    st.divider()
    repo_path = st.text_input("Local Git Repo Path", value=".")
    if st.button("Scan Uncommitted Git Diff"):
        try:
            diff_text = get_local_git_diff(repo_path=repo_path)
            if not diff_text:
                st.warning("No uncommitted changes detected in that repo.")
            else:
                st.session_state["pending_input"] = (diff_text, "git.diff", True)
        except Exception as e:
            st.error(str(e))

if "messages" not in st.session_state:
    st.session_state.messages = []

for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        if "meta" in msg:
            st.caption(msg["meta"])
        st.markdown(msg["content"])

prompt = st.chat_input("Paste a Git diff, vulnerable snippet, or ask a security question...")

active_payload = None
if "pending_input" in st.session_state:
    active_payload = st.session_state.pop("pending_input")
elif uploaded_file is not None and st.sidebar.button("Audit Uploaded File"):
    file_text = uploaded_file.read().decode("utf-8", errors="replace")
    active_payload = (file_text, uploaded_file.name, True)
elif prompt:
    active_payload = (prompt, None, force_audit)

if active_payload:
    raw_text, fname, f_audit = active_payload
    display_user = f"**Uploaded `{fname}`**\n```\n{raw_text[:1500]}\n```" if fname else raw_text
    st.session_state.messages.append({"role": "user", "content": display_user})
    with st.chat_message("user"):
        st.markdown(display_user)

    with st.chat_message("assistant"):
        with st.spinner("Running local audit on GPU..."):
            route, reply, tps = run_codewarden(raw_text, filename=fname, force_audit=f_audit)
            meta = f"Mode: `{route.mode}` • Detected: `{route.language}` • Speed: `{tps:.1f} tok/s`"
            st.caption(meta)
            st.markdown(reply)
            st.session_state.messages.append({"role": "assistant", "content": reply, "meta": meta})
