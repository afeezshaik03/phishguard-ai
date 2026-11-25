import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import sys, os, time

sys.path.append(os.path.dirname(__file__))
from database import get_all_threats, get_stats, init_db

# ── Page config ───────────────────────────────────────────
st.set_page_config(
    page_title = "SOC Dashboard — AI Phishing Detector",
    page_icon  = "🛡️",
    layout     = "wide",
    initial_sidebar_state = "expanded"
)

# ── Custom CSS ────────────────────────────────────────────
st.markdown("""

""", unsafe_allow_html=True)

# ── Header ────────────────────────────────────────────────
st.markdown("""

  

    🛡️ SOC Dashboard — AI Phishing Detector
  

  

    Real-time threat monitoring · ML-powered detection
  



""", unsafe_allow_html=True)

# ── Auto refresh ──────────────────────────────────────────
with st.sidebar:
    st.markdown("### ⚙️ Dashboard Controls")
    auto_refresh = st.toggle("Auto Refresh", value=True)
    refresh_rate = st.slider("Refresh every (seconds)",
                              5, 60, 10)
    st.markdown("---")
    st.markdown("### 🔍 Filters")
    risk_filter = st.multiselect(
        "Risk Level",
        ["DANGEROUS","SUSPICIOUS","LOW RISK","SAFE"],
        default=["DANGEROUS","SUSPICIOUS","LOW RISK","SAFE"]
    )
    show_phishing_only = st.checkbox("Show phishing only")
    st.markdown("---")
    st.markdown("### 📊 About")
    st.info("Live SOC dashboard connected to Chrome Extension via Flask API + SQLite")

# ── Load data ─────────────────────────────────────────────
init_db()
threats = get_all_threats()
stats   = get_stats()

# ── KPI Metrics ───────────────────────────────────────────
st.markdown("### 📊 Live Threat Statistics")
c1, c2, c3, c4, c5 = st.columns(5)

c1.metric("🔍 Total Scanned",  stats["total"],
          delta=f"+{stats['today']} today")
c2.metric("🔴 Phishing Found", stats["phishing"],
          delta="threats detected")
c3.metric("🟢 Safe Sites",     stats["safe"])
c4.metric("⚠️ Avg Risk Score", f"{stats['avg_risk']}%")
c5.metric("📅 Scanned Today",  stats["today"])

st.markdown("---")

# ── Charts Row ────────────────────────────────────────────
if threats:
    df = pd.DataFrame(threats)
    df["detected_at"] = pd.to_datetime(df["detected_at"])
    df["hour"]        = df["detected_at"].dt.strftime("%H:00")
    df["date"]        = df["detected_at"].dt.date

    col1, col2 = st.columns(2)

    # Chart 1: Pie chart
    with col1:
        st.markdown("#### 🥧 Threat Distribution")
        level_counts = df["risk_level"].value_counts()
        color_map = {
            "DANGEROUS" : "#E24B4A",
            "SUSPICIOUS": "#F59E0B",
            "LOW RISK"  : "#3B82F6",
            "SAFE"      : "#1D9E75"
        }
        fig_pie = px.pie(
            values = level_counts.values,
            names  = level_counts.index,
            color  = level_counts.index,
            color_discrete_map = color_map,
            hole   = 0.4
        )
        fig_pie.update_layout(
            paper_bgcolor = "#1a1a2e",
            plot_bgcolor  = "#1a1a2e",
            font_color    = "#ffffff",
            margin        = dict(t=20,b=20,l=20,r=20)
        )
        st.plotly_chart(fig_pie, width="stretch")

    # Chart 2: Risk score over time
    with col2:
        st.markdown("#### 📈 Risk Score Timeline")
        fig_line = px.line(
            df.head(50).sort_values("detected_at"),
            x     = "detected_at",
            y     = "risk_score",
            color_discrete_sequence = ["#534AB7"]
        )
        fig_line.add_hline(y=80, line_dash="dash",
                           line_color="#E24B4A",
                           annotation_text="Danger (80%)")
        fig_line.add_hline(y=50, line_dash="dash",
                           line_color="#F59E0B",
                           annotation_text="Suspicious (50%)")
        fig_line.update_layout(
            paper_bgcolor = "#1a1a2e",
            plot_bgcolor  = "#1a1a2e",
            font_color    = "#ffffff",
            xaxis_title   = "Time",
            yaxis_title   = "Risk Score (%)",
            margin        = dict(t=20,b=20,l=20,r=20)
        )
        st.plotly_chart(fig_line, width="stretch")

    # Chart 3: Hourly threat volume bar chart
    st.markdown("#### 📊 Hourly Threat Volume")
    hourly = df.groupby(["hour","risk_level"]).size()\
               .reset_index(name="count")
    fig_bar = px.bar(
        hourly, x="hour", y="count",
        color="risk_level",
        color_discrete_map=color_map,
        barmode="stack"
    )
    fig_bar.update_layout(
        paper_bgcolor = "#1a1a2e",
        plot_bgcolor  = "#1a1a2e",
        font_color    = "#ffffff",
        xaxis_title   = "Hour of Day",
        yaxis_title   = "Number of URLs Scanned",
        margin        = dict(t=20,b=20,l=20,r=20)
    )
    st.plotly_chart(fig_bar, width="stretch")

    st.markdown("---")

    # ── Alert Log Table ───────────────────────────────────
    st.markdown("### 🚨 Live Alert Log")

    # Apply filters
    filtered = df.copy()
    if risk_filter:
        filtered = filtered[
            filtered["risk_level"].isin(risk_filter)]
    if show_phishing_only:
        filtered = filtered[filtered["is_phishing"] == 1]

    # Color code the risk level
    def color_risk(val):
        colors = {
            "DANGEROUS" : "background-color:#7f1d1d;color:#fca5a5",
            "SUSPICIOUS": "background-color:#78350f;color:#fde68a",
            "LOW RISK"  : "background-color:#1e3a5f;color:#bfdbfe",
            "SAFE"      : "background-color:#064e3b;color:#6ee7b7"
        }
        return colors.get(val, "")

    display_df = filtered[[
        "detected_at","url","risk_score",
        "risk_level","top_reasons"
    ]].copy()
    display_df["url"] = display_df["url"].str[:60] + "..."
    display_df.columns = [
        "Detected At","URL",
        "Risk Score (%)","Risk Level","Flagged Features"
    ]

    st.dataframe(
        display_df.head(100).style.map(
         color_risk, subset=["Risk Level"]
         ),
        use_container_width = True,
        height = 400
    )

    # ── IOC Tracker ──────────────────────────────────────
    st.markdown("---")
    st.markdown("### 🎯 IOC Tracker — Top Flagged Features")

    all_reasons = []
    for r in df[df["is_phishing"]==1]["top_reasons"]:
        if r and r != "None":
            cleaned = r.strip("[]'").replace("'","")
            all_reasons.extend(
                [x.strip() for x in cleaned.split(",")])

    if all_reasons:
        reason_counts = pd.Series(all_reasons)\
                          .value_counts().head(10)
        fig_ioc = px.bar(
            x     = reason_counts.values,
            y     = reason_counts.index,
            orientation = "h",
            color_discrete_sequence = ["#E24B4A"]
        )
        fig_ioc.update_layout(
            paper_bgcolor = "#1a1a2e",
            plot_bgcolor  = "#1a1a2e",
            font_color    = "#ffffff",
            xaxis_title   = "Times Flagged",
            yaxis_title   = "Feature (IOC)",
            margin        = dict(t=10,b=20,l=20,r=20)
        )
        st.plotly_chart(fig_ioc, width="stretch")

else:
    st.info("🔍 No threats logged yet. Browse some websites with your Chrome Extension running to start seeing data here!")

# ── Auto refresh ──────────────────────────────────────────
if auto_refresh:
    time.sleep(refresh_rate)
    st.rerun()