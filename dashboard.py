import dash
from dash import dcc, html, dash_table
from dash.dependencies import Input, Output
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import sqlite3
from geoip import get_location

app = dash.Dash(__name__)

COLORS = {
    'background': '#1e1e2e',
    'card': '#2a2a3e',
    'attack': '#ff4757',
    'normal': '#2ed573',
    'text': '#ffffff',
    'muted': '#a0a0b0'
}

def get_data():
    try:
        conn = sqlite3.connect('logs/alerts.db')
        df = pd.read_sql_query("SELECT * FROM alerts ORDER BY id DESC", conn)
        conn.close()
        return df
    except:
        return pd.DataFrame(columns=['id','timestamp','src_ip','dst_ip',
                                     'protocol','src_port','dst_port',
                                     'prediction','src_bytes'])

def enrich_with_geo(df):
    locations = []
    for ip in df['src_ip']:
        loc = get_location(ip)
        locations.append(loc)
    df['country'] = [l['country'] for l in locations]
    df['city'] = [l['city'] for l in locations]
    df['lat'] = [l['lat'] for l in locations]
    df['lon'] = [l['lon'] for l in locations]
    return df

def make_card(title, value, color):
    return html.Div(style={
        'backgroundColor': COLORS['card'],
        'borderRadius': '10px',
        'padding': '20px',
        'textAlign': 'center',
        'minWidth': '150px',
        'borderTop': f'3px solid {color}'
    }, children=[
        html.H2(str(value), style={'color': color, 'margin': '0', 'fontSize': '36px'}),
        html.P(title, style={'color': COLORS['muted'], 'margin': '5px 0 0 0'})
    ])

app.layout = html.Div(style={
    'backgroundColor': COLORS['background'],
    'minHeight': '100vh',
    'padding': '20px',
    'fontFamily': 'Arial'
}, children=[

    # Header
    html.Div(style={'textAlign': 'center', 'marginBottom': '30px'}, children=[
        html.H1("🛡️ Network Intrusion Detection System",
                style={'color': COLORS['text'], 'fontSize': '28px'}),
        html.P("Real-time network traffic monitoring dashboard",
               style={'color': COLORS['muted']})
    ]),

    # Stats cards
    html.Div(id='stats-cards', style={
        'display': 'flex',
        'gap': '20px',
        'marginBottom': '30px',
        'justifyContent': 'center'
    }),

    # Pie + Protocol charts
    html.Div(style={'display': 'flex', 'gap': '20px', 'marginBottom': '20px'}, children=[
        html.Div(style={
            'flex': '1',
            'backgroundColor': COLORS['card'],
            'borderRadius': '10px',
            'padding': '15px'
        }, children=[dcc.Graph(id='pie-chart')]),

        html.Div(style={
            'flex': '2',
            'backgroundColor': COLORS['card'],
            'borderRadius': '10px',
            'padding': '15px'
        }, children=[dcc.Graph(id='protocol-chart')]),
    ]),

    # 🌍 GeoIP World Map
    html.Div(style={
        'backgroundColor': COLORS['card'],
        'borderRadius': '10px',
        'padding': '15px',
        'marginBottom': '20px'
    }, children=[
        html.H3("🌍 Attack Origins Map",
                style={'color': COLORS['text'], 'marginBottom': '15px'}),
        dcc.Graph(id='geo-map')
    ]),

    # Top attacking IPs
    html.Div(style={
        'backgroundColor': COLORS['card'],
        'borderRadius': '10px',
        'padding': '15px',
        'marginBottom': '20px'
    }, children=[
        html.H3("🔥 Top Attacking IPs",
                style={'color': COLORS['text'], 'marginBottom': '15px'}),
        dcc.Graph(id='top-ips-chart')
    ]),

    # Alerts table
    html.Div(style={
        'backgroundColor': COLORS['card'],
        'borderRadius': '10px',
        'padding': '15px',
        'marginBottom': '20px'
    }, children=[
        html.H3("Recent Alerts",
                style={'color': COLORS['text'], 'marginBottom': '15px'}),
        html.Div(id='alerts-table')
    ]),

    dcc.Interval(id='interval', interval=5000, n_intervals=0)
])

@app.callback(
    [Output('stats-cards', 'children'),
     Output('pie-chart', 'figure'),
     Output('protocol-chart', 'figure'),
     Output('geo-map', 'figure'),
     Output('top-ips-chart', 'figure'),
     Output('alerts-table', 'children')],
    [Input('interval', 'n_intervals')]
)
def update_dashboard(n):
    df = get_data()
    empty_fig = go.Figure()
    empty_fig.update_layout(
        paper_bgcolor=COLORS['card'],
        plot_bgcolor=COLORS['card'],
        font_color=COLORS['text']
    )

    if df.empty:
        return [], empty_fig, empty_fig, empty_fig, empty_fig, \
               html.P("No alerts yet — run detect.py first",
                      style={'color': COLORS['muted']})

    total = len(df)
    attacks = len(df[df['prediction'] == 'attack'])
    normals = len(df[df['prediction'] == 'normal'])
    attack_df = df[df['prediction'] == 'attack']

    # Stats cards
    cards = [
        make_card("Total Packets", total, COLORS['text']),
        make_card("⚠️ Attacks", attacks, COLORS['attack']),
        make_card("✅ Normal", normals, COLORS['normal']),
        make_card("Protocols", df['protocol'].nunique(), '#ffa502')
    ]

    # Pie chart
    pie = px.pie(
        values=[attacks, normals],
        names=['Attack', 'Normal'],
        color_discrete_sequence=[COLORS['attack'], COLORS['normal']],
        title='Traffic Classification'
    )
    pie.update_layout(
        paper_bgcolor=COLORS['card'],
        plot_bgcolor=COLORS['card'],
        font_color=COLORS['text'],
        title_font_color=COLORS['text']
    )

    # Protocol chart
    proto_counts = df.groupby(['protocol', 'prediction']).size().reset_index(name='count')
    bar = px.bar(
        proto_counts, x='protocol', y='count', color='prediction',
        color_discrete_map={'attack': COLORS['attack'], 'normal': COLORS['normal']},
        title='Traffic by Protocol',
        barmode='group'
    )
    bar.update_layout(
        paper_bgcolor=COLORS['card'],
        plot_bgcolor=COLORS['card'],
        font_color=COLORS['text'],
        title_font_color=COLORS['text']
    )

    # 🌍 GeoIP Map
    geo_df = enrich_with_geo(attack_df.copy())
    geo_df = geo_df[geo_df['country'] != 'Local Network']
    geo_df = geo_df[geo_df['country'] != 'Unknown']

    if not geo_df.empty:
        geo_map = px.scatter_geo(
            geo_df,
            lat='lat',
            lon='lon',
            color='protocol',
            hover_name='country',
            hover_data=['city', 'src_ip', 'src_bytes'],
            title='Attack Origins',
            size='src_bytes',
            size_max=20,
            projection='natural earth'
        )
        geo_map.update_layout(
            paper_bgcolor=COLORS['card'],
            plot_bgcolor=COLORS['card'],
            font_color=COLORS['text'],
            title_font_color=COLORS['text'],
            geo=dict(
                bgcolor=COLORS['card'],
                landcolor='#3a3a5e',
                oceancolor='#1e1e3e',
                showocean=True,
                showland=True,
                showcountries=True,
                countrycolor='#555577'
            )
        )
    else:
        geo_map = empty_fig
        geo_map.add_annotation(
            text="No external attack IPs to map yet",
            showarrow=False,
            font=dict(color=COLORS['muted'], size=14),
            xref="paper", yref="paper", x=0.5, y=0.5
        )

    # Top attacking IPs
    top_ips = attack_df['src_ip'].value_counts().head(5).reset_index()
    top_ips.columns = ['IP', 'Count']
    top_chart = px.bar(
        top_ips, x='Count', y='IP',
        orientation='h',
        title='Top 5 Attacking IPs',
        color='Count',
        color_continuous_scale=['#ff6b81', '#ff4757']
    )
    top_chart.update_layout(
        paper_bgcolor=COLORS['card'],
        plot_bgcolor=COLORS['card'],
        font_color=COLORS['text'],
        title_font_color=COLORS['text'],
        yaxis={'categoryorder': 'total ascending'}
    )

    # Alerts table
    table = dash_table.DataTable(
        data=df.head(20).to_dict('records'),
        columns=[
            {'name': 'Time', 'id': 'timestamp'},
            {'name': 'Status', 'id': 'prediction'},
            {'name': 'Protocol', 'id': 'protocol'},
            {'name': 'Source IP', 'id': 'src_ip'},
            {'name': 'Destination IP', 'id': 'dst_ip'},
            {'name': 'Bytes', 'id': 'src_bytes'},
        ],
        style_table={'overflowX': 'auto'},
        style_cell={
            'backgroundColor': COLORS['card'],
            'color': COLORS['text'],
            'border': '1px solid #444',
            'padding': '8px'
        },
        style_header={
            'backgroundColor': '#1a1a2e',
            'color': COLORS['text'],
            'fontWeight': 'bold'
        },
        style_data_conditional=[
            {'if': {'filter_query': '{prediction} = attack'},
             'color': COLORS['attack']},
            {'if': {'filter_query': '{prediction} = normal'},
             'color': COLORS['normal']}
        ]
    )

    return cards, pie, bar, geo_map, top_chart, table

if __name__ == '__main__':
    app.run(debug=True)