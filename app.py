"""Cybersecurity & Password Security Analyzer - Streamlit Dashboard

A comprehensive web application for password security assessment.
"""

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from src.password_analyzer import PasswordAnalyzer
from src.hash_comparator import HashComparator
from src.vulnerability_scanner import VulnerabilityScanner
from src.recommendation_engine import RecommendationEngine
import time

# Page configuration
st.set_page_config(
    page_title="Cybersecurity Password Analyzer",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        font-weight: bold;
        text-align: center;
        color: #1f77b4;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
    }
    .strength-very-weak { color: #d62728; }
    .strength-weak { color: #ff7f0e; }
    .strength-moderate { color: #ffbb00; }
    .strength-strong { color: #2ca02c; }
    .strength-very-strong { color: #006400; }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'analysis_history' not in st.session_state:
    st.session_state.analysis_history = []

# Sidebar navigation
st.sidebar.title("🔐 Security Analyzer")
st.sidebar.markdown("---")

page = st.sidebar.radio(
    "Navigation",
    ["🏠 Home", "🔍 Password Analyzer", "#️⃣ Hash Comparator", 
     "🛡️ Vulnerability Scanner", "📚 Educational Dashboard", "📊 Statistics"]
)

st.sidebar.markdown("---")
st.sidebar.info(
    "**Created by:** Abhinav T S\n\n"
    "**Project:** Demonstrating enterprise password protection strategies\n\n"
    "**Internships:** Goldman Sachs & Mastercard"
)

# ============================================================================
# HOME PAGE
# ============================================================================
if page == "🏠 Home":
    st.markdown('<div class="main-header">🔐 Cybersecurity & Password Security Analyzer</div>', unsafe_allow_html=True)
    
    st.markdown("""
    ### Welcome to the Password Security Assessment Platform
    
    This tool combines cybersecurity principles from **Goldman Sachs** and **Mastercard** internships 
    to deliver comprehensive password security analysis.
    """)
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        #### 🔍 Password Analysis
        - Real-time strength evaluation
        - Entropy calculation
        - Pattern detection
        - Crack time estimation
        """)
    
    with col2:
        st.markdown("""
        #### #️⃣ Hash Comparison
        - Multiple algorithms
        - Performance benchmarking
        - Security analysis
        - Rainbow table demo
        """)
    
    with col3:
        st.markdown("""
        #### 🛡️ Security Scanner
        - Common password detection
        - Vulnerability assessment
        - Compliance checking
        - Best practice recommendations
        """)
    
    st.markdown("---")
    
    st.markdown("""
    ### 🚀 Quick Start
    
    1. **Navigate** to the Password Analyzer from the sidebar
    2. **Enter** a password to analyze
    3. **Review** the comprehensive security assessment
    4. **Explore** hash comparison and vulnerability scanning
    5. **Learn** from the educational dashboard
    
    ### 🎯 Key Features
    
    - **Enterprise-grade** security assessment
    - **Real-time** analysis and feedback
    - **Multiple** hashing algorithm comparison
    - **Educational** resources on password security
    - **Compliance** with NIST and OWASP standards
    """)

# ============================================================================
# PASSWORD ANALYZER PAGE
# ============================================================================
elif page == "🔍 Password Analyzer":
    st.title("🔍 Password Strength Analyzer")
    st.markdown("Comprehensive password security assessment with real-time feedback.")
    
    # Password input
    col1, col2 = st.columns([3, 1])
    with col1:
        password_input = st.text_input(
            "Enter password to analyze:",
            type="password",
            help="Your password is analyzed locally and never stored or transmitted."
        )
    with col2:
        show_password = st.checkbox("Show password", value=False)
        if show_password and password_input:
            st.code(password_input)
    
    if password_input:
        # Initialize analyzers
        analyzer = PasswordAnalyzer()
        vuln_scanner = VulnerabilityScanner()
        rec_engine = RecommendationEngine()
        
        # Perform analysis
        with st.spinner("Analyzing password..."):
            analysis = analyzer.analyze(password_input)
            vuln_result = vuln_scanner.scan(password_input)
            recommendations = rec_engine.generate(analysis)
        
        # Display results
        st.markdown("---")
        
        # Main metrics
        col1, col2, col3, col4 = st.columns(4)
        
        strength_class = f"strength-{analysis['strength_level'].lower().replace(' ', '-')}"
        
        with col1:
            st.metric("Strength Level", analysis['strength_level'])
        with col2:
            st.metric("Overall Score", f"{analysis['score']}/100")
        with col3:
            st.metric("Entropy", f"{analysis['entropy']:.1f} bits")
        with col4:
            st.metric("Crack Time", analysis['crack_time'])
        
        # Strength gauge
        st.markdown("#### Password Strength Gauge")
        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number",
            value=analysis['score'],
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': "Security Score"},
            gauge={
                'axis': {'range': [0, 100]},
                'bar': {'color': "darkblue"},
                'steps': [
                    {'range': [0, 20], 'color': "#d62728"},
                    {'range': [20, 40], 'color': "#ff7f0e"},
                    {'range': [40, 60], 'color': "#ffbb00"},
                    {'range': [60, 80], 'color': "#2ca02c"},
                    {'range': [80, 100], 'color': "#006400"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 60
                }
            }
        ))
        fig_gauge.update_layout(height=300)
        st.plotly_chart(fig_gauge, use_container_width=True)
        
        # Character analysis
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### Character Composition")
            char_data = analysis['character_analysis']
            char_df = pd.DataFrame({
                'Type': ['Lowercase', 'Uppercase', 'Digits', 'Special', 'Unique'],
                'Count': [
                    char_data['lowercase'],
                    char_data['uppercase'],
                    char_data['digits'],
                    char_data['special'],
                    char_data['unique_chars']
                ]
            })
            fig_char = px.bar(char_df, x='Type', y='Count', 
                             color='Count',
                             color_continuous_scale='Blues')
            fig_char.update_layout(height=300, showlegend=False)
            st.plotly_chart(fig_char, use_container_width=True)
        
        with col2:
            st.markdown("#### Pattern Detection")
            patterns = analysis['pattern_analysis']
            pattern_labels = []
            pattern_values = []
            
            for key, value in patterns.items():
                if value:
                    label = key.replace('_', ' ').title()
                    pattern_labels.append(label)
                    pattern_values.append(1)
            
            if pattern_labels:
                st.warning("⚠️ Detected Patterns:")
                for label in pattern_labels:
                    st.markdown(f"- {label}")
            else:
                st.success("✅ No common patterns detected")
        
        # Vulnerability scan
        st.markdown("---")
        st.markdown("#### 🛡️ Vulnerability Assessment")
        
        if vuln_result['is_common']:
            st.error(f"🚨 **CRITICAL:** This is a common password found in breach databases!")
            st.markdown(vuln_result['recommendation'])
        else:
            st.success(f"✅ Password not found in common password database ({vuln_result['checked_against']} passwords checked)")
        
        # Recommendations
        st.markdown("---")
        st.markdown("#### 💡 Security Recommendations")
        
        for i, rec in enumerate(recommendations, 1):
            st.markdown(f"{i}. {rec}")
        
        # Save to history
        st.session_state.analysis_history.append({
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'length': analysis['length'],
            'score': analysis['score'],
            'strength': analysis['strength_level'],
            'entropy': analysis['entropy']
        })

# ============================================================================
# HASH COMPARATOR PAGE
# ============================================================================
elif page == "#️⃣ Hash Comparator":
    st.title("#️⃣ Hash Algorithm Comparator")
    st.markdown("Compare different hashing algorithms for password storage.")
    
    tab1, tab2, tab3 = st.tabs(["Algorithm Comparison", "Hash Generator", "Rainbow Table Demo"])
    
    with tab1:
        st.markdown("### Performance Benchmark")
        
        test_password = st.text_input("Enter test password:", value="TestPassword123!", type="password")
        iterations = st.slider("Benchmark iterations:", 10, 1000, 100)
        
        if st.button("Run Benchmark"):
            comparator = HashComparator()
            
            with st.spinner("Running benchmark..."):
                results = comparator.compare_all(test_password, iterations)
            
            # Create comparison table
            comparison_data = []
            for algo, data in results.items():
                if algo not in ['security_analysis', 'recommendations']:
                    comparison_data.append({
                        'Algorithm': data['algorithm'].upper(),
                        'Avg Time (ms)': data['avg_time_ms'],
                        'Hash Length': data['hash_length'],
                        'Security': data['security_rating']
                    })
            
            df = pd.DataFrame(comparison_data)
            st.dataframe(df, use_container_width=True)
            
            # Visualization
            fig = px.bar(df, x='Algorithm', y='Avg Time (ms)', 
                        color='Algorithm',
                        title='Hash Algorithm Performance Comparison')
            st.plotly_chart(fig, use_container_width=True)
            
            # Security analysis
            st.markdown("### Security Analysis")
            for algo, details in results['security_analysis'].items():
                with st.expander(f"{algo.upper()} - {details['year_introduced']}"):
                    st.markdown(f"**Use Case:** {details['use_case']}")
                    st.markdown("**Vulnerabilities:**")
                    for vuln in details['vulnerabilities']:
                        st.markdown(f"- {vuln}")
            
            # Recommendations
            st.markdown("### 💡 Recommendations")
            for rec in results['recommendations']:
                st.markdown(f"- {rec}")
    
    with tab2:
        st.markdown("### Hash Generator")
        
        password = st.text_input("Password to hash:", type="password", key="hash_gen")
        algorithm = st.selectbox("Select algorithm:", ['md5', 'sha1', 'sha256', 'sha512', 'bcrypt'])
        
        if st.button("Generate Hash") and password:
            comparator = HashComparator()
            result = comparator.hash_password(password, algorithm)
            
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Algorithm", result['algorithm'].upper())
                st.metric("Time Taken", f"{result['time_taken']:.4f} ms")
            with col2:
                st.metric("Hash Length", result['hash_length'])
                st.metric("Security Rating", comparator._get_security_rating(algorithm))
            
            st.markdown("**Generated Hash:**")
            st.code(result['hash'])
            
            if result['salt'] and result['salt'] != 'Included in hash':
                st.markdown("**Salt:**")
                st.code(result['salt'])
    
    with tab3:
        st.markdown("### Rainbow Table Vulnerability Demonstration")
        st.markdown("""
        Rainbow tables are precomputed hash databases used to crack passwords. 
        This demonstration shows why salting is critical.
        """)
        
        demo_password = st.text_input("Enter password for demo:", value="password123", key="rainbow")
        
        if st.button("Run Demo"):
            comparator = HashComparator()
            demo_result = comparator.demonstrate_rainbow_table_vulnerability(demo_password)
            
            st.markdown("#### Unsalted Hashes (Vulnerable)")
            st.warning("⚠️ These can be looked up in rainbow tables instantly!")
            for algo, hash_val in demo_result['unsalted_hashes'].items():
                st.code(f"{algo.upper()}: {hash_val}")
            
            st.markdown("#### Salted Hashes (Protected)")
            st.success("✅ Unique salt makes rainbow table attacks impractical")
            for algo, data in demo_result['salted_hashes'].items():
                st.code(f"{algo.upper()}: {data['hash']}")
                st.caption(f"Salt: {data['salt']}")
            
            st.info(demo_result['explanation'])

# ============================================================================
# VULNERABILITY SCANNER PAGE
# ============================================================================
elif page == "🛡️ Vulnerability Scanner":
    st.title("🛡️ Password Vulnerability Scanner")
    st.markdown("Scan passwords against known weak and compromised password databases.")
    
    scanner = VulnerabilityScanner()
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        password = st.text_input("Enter password to scan:", type="password")
    
    with col2:
        st.metric("Database Size", f"{len(scanner.common_passwords):,} passwords")
    
    if password:
        result = scanner.scan(password)
        
        st.markdown("---")
        
        if result['is_common']:
            st.error("🚨 **VULNERABILITY DETECTED**")
            st.markdown("""
            ### This password appears in common password lists!
            
            **Risk Level:** CRITICAL  
            **Recommendation:** Change this password immediately
            
            **Why this matters:**
            - This password is likely in hacker databases
            - Automated attacks will try this password first
            - It may have been exposed in previous data breaches
            """)
        else:
            st.success("✅ **Password Not Found in Common Lists**")
            st.markdown("""
            ### Good news!
            
            This password was not found in our database of common weak passwords.
            However, this doesn't guarantee complete security.
            
            **Additional recommendations:**
            - Ensure it's unique to this account
            - Check password strength in the analyzer
            - Enable two-factor authentication
            - Use a password manager
            """)
        
        # Additional security tips
        st.markdown("---")
        st.markdown("### 🔒 Password Security Best Practices")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            **DO:**
            - Use unique passwords for each account
            - Use 12+ characters minimum
            - Mix uppercase, lowercase, numbers, symbols
            - Use a password manager
            - Enable two-factor authentication
            - Update passwords periodically
            """)
        
        with col2:
            st.markdown("""
            **DON'T:**
            - Reuse passwords across accounts
            - Use personal information (names, dates)
            - Use common words or patterns
            - Share passwords via email/text
            - Store passwords in plain text
            - Use dictionary words
            """)

# ============================================================================
# EDUCATIONAL DASHBOARD PAGE
# ============================================================================
elif page == "📚 Educational Dashboard":
    st.title("📚 Password Security Education")
    
    tab1, tab2, tab3, tab4 = st.tabs(["Security Principles", "Attack Methods", "Best Practices", "Compliance Standards"])
    
    with tab1:
        st.markdown("### 🔐 Core Security Principles")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            #### Cryptographic Hashing
            - **One-way function:** Cannot reverse hash to get password
            - **Deterministic:** Same input always produces same output
            - **Avalanche effect:** Small change = completely different hash
            
            #### Salting
            - **Unique salt per password** prevents rainbow table attacks
            - **Random generation** ensures unpredictability
            - **Salt storage** alongside hash is acceptable
            """)
        
        with col2:
            st.markdown("""
            #### Key Stretching
            - **Multiple iterations** increase computation time
            - **Work factor** adjustable for future-proofing
            - **bcrypt, scrypt, Argon2** designed for this purpose
            
            #### Password Entropy
            - **Measures unpredictability** in bits
            - **Higher entropy** = harder to crack
            - **Calculated from:** length × log₂(character set size)
            """)
        
        # Entropy calculator
        st.markdown("---")
        st.markdown("#### Entropy Calculator")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            pwd_length = st.slider("Password Length", 4, 32, 12)
        with col2:
            char_types = st.multiselect(
                "Character Types",
                ['Lowercase (26)', 'Uppercase (26)', 'Digits (10)', 'Symbols (32)'],
                default=['Lowercase (26)', 'Uppercase (26)', 'Digits (10)']
            )
        
        charset_size = sum([26 if 'Lowercase' in t else 26 if 'Uppercase' in t else 10 if 'Digits' in t else 32 for t in char_types])
        
        if charset_size > 0:
            import math
            entropy = pwd_length * math.log2(charset_size)
            with col3:
                st.metric("Entropy", f"{entropy:.1f} bits")
            
            st.info(f"""A {pwd_length}-character password with {charset_size} possible characters has {entropy:.1f} bits of entropy. 
            This represents 2^{entropy:.1f} = {2**entropy:.2e} possible combinations.""")
    
    with tab2:
        st.markdown("### ⚔️ Common Attack Methods")
        
        attack_data = [
            {
                'name': 'Brute Force Attack',
                'description': 'Tries every possible combination',
                'effectiveness': 'Depends on password length and complexity',
                'defense': 'Use long, complex passwords (16+ characters)'
            },
            {
                'name': 'Dictionary Attack',
                'description': 'Tries common words and phrases',
                'effectiveness': 'Very effective against common passwords',
                'defense': 'Avoid dictionary words, use random characters'
            },
            {
                'name': 'Rainbow Table Attack',
                'description': 'Uses precomputed hash tables',
                'effectiveness': 'Instant for unsalted hashes',
                'defense': 'Always use unique salts'
            },
            {
                'name': 'Credential Stuffing',
                'description': 'Reuses leaked credentials across sites',
                'effectiveness': 'High if passwords are reused',
                'defense': 'Use unique passwords per account'
            },
            {
                'name': 'Phishing',
                'description': 'Tricks users into revealing passwords',
                'effectiveness': 'Social engineering dependent',
                'defense': 'User education, 2FA, password managers'
            }
        ]
        
        for attack in attack_data:
            with st.expander(f"**{attack['name']}**"):
                st.markdown(f"**Description:** {attack['description']}")
                st.markdown(f"**Effectiveness:** {attack['effectiveness']}")
                st.markdown(f"**Defense:** {attack['defense']}")
    
    with tab3:
        st.markdown("### ✅ Password Best Practices")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            #### For Users
            1. **Length over complexity**: 16+ random characters
            2. **Unique passwords**: Never reuse across accounts
            3. **Password manager**: Generate and store securely
            4. **Two-factor authentication**: Always enable when available
            5. **Passphrase strategy**: Multiple random words
            6. **Regular updates**: Change after breaches
            7. **Secure storage**: Never write down or email
            """)
        
        with col2:
            st.markdown("""
            #### For Developers
            1. **Use bcrypt/Argon2**: Never plain text or MD5/SHA1
            2. **Salt every password**: Unique per user
            3. **Minimum length**: Enforce 12+ characters
            4. **Rate limiting**: Prevent brute force attempts
            5. **Secure transmission**: Always use HTTPS
            6. **Breach notification**: Alert users immediately
            7. **Security audits**: Regular penetration testing
            """)
    
    with tab4:
        st.markdown("### 📋 Compliance Standards")
        
        st.markdown("#### NIST SP 800-63B Guidelines")
        st.info("""
        - Minimum 8 characters for user-chosen passwords
        - Minimum 6 characters for system-generated passwords
        - Maximum length should allow at least 64 characters
        - Check against known breached password databases
        - No composition rules (no forced special characters)
        - No mandatory periodic changes
        - Implement rate limiting and account lockout
        """)
        
        st.markdown("#### OWASP Recommendations")
        st.info("""
        - Implement password strength meters
        - Use bcrypt, scrypt, or Argon2 for hashing
        - Minimum 12 characters recommended
        - Implement multi-factor authentication
        - Secure password recovery mechanisms
        - Protect against automated attacks
        - Educate users on password security
        """)
        
        st.markdown("#### PCI DSS Requirements")
        st.info("""
        - Encrypt passwords using strong cryptography
        - Minimum 7 characters
        - Must contain numeric and alphabetic characters
        - Change passwords every 90 days
        - Remember last 4 passwords to prevent reuse
        - Lock account after 6 failed attempts
        """)

# ============================================================================
# STATISTICS PAGE
# ============================================================================
elif page == "📊 Statistics":
    st.title("📊 Analysis Statistics")
    
    if not st.session_state.analysis_history:
        st.info("No analysis history yet. Analyze some passwords to see statistics!")
    else:
        df = pd.DataFrame(st.session_state.analysis_history)
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Analyses", len(df))
        with col2:
            st.metric("Avg Score", f"{df['score'].mean():.1f}")
        with col3:
            st.metric("Avg Length", f"{df['length'].mean():.1f}")
        with col4:
            st.metric("Avg Entropy", f"{df['entropy'].mean():.1f} bits")
        
        # Score distribution
        st.markdown("### Score Distribution")
        fig = px.histogram(df, x='score', nbins=20, 
                          title='Password Score Distribution',
                          labels={'score': 'Security Score', 'count': 'Frequency'})
        st.plotly_chart(fig, use_container_width=True)
        
        # Strength levels
        st.markdown("### Strength Levels")
        strength_counts = df['strength'].value_counts()
        fig = px.pie(values=strength_counts.values, names=strength_counts.index,
                    title='Password Strength Distribution')
        st.plotly_chart(fig, use_container_width=True)
        
        # Timeline
        st.markdown("### Analysis Timeline")
        fig = px.scatter(df, x='timestamp', y='score', color='strength',
                        title='Password Scores Over Time')
        st.plotly_chart(fig, use_container_width=True)
        
        # Clear history button
        if st.button("Clear History"):
            st.session_state.analysis_history = []
            st.rerun()
