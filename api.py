from flask import Blueprint, jsonify, make_response, request
from data import db_session
from data.models import User, Match, RPLTable
from datetime import datetime

blueprint = Blueprint(
    'football_api',
    __name__,
    template_folder='templates'
)


def get_users():
    db_sess = db_session.create_session()
    users = db_sess.query(User).all()
    return jsonify({
        'users': [user.to_dict(only=('id', 'name', 'email', 'club', 'is_admin'))
                  for user in users]
    })


@blueprint.route('/api/users/<int:user_id>')
def get_user(user_id):
    db_sess = db_session.create_session()
    user = db_sess.query(User).get(user_id)
    return jsonify({
        'user': user.to_dict(only=('id', 'name', 'email', 'club', 'is_admin'))
    })


@blueprint.route('/api/matches')
def get_matches():
    db_sess = db_session.create_session()
    matches = db_sess.query(Match).all()
    return jsonify({
        'matches': [match.to_dict(only=(
            'id', 'home_team', 'away_team', 'match_date',
            'home_score', 'away_score', 'is_played', 'tour_number'
        )) for match in matches]
    })


@blueprint.route('/api/matches/<int:match_id>')
def get_match(match_id):
    db_sess = db_session.create_session()
    match = db_sess.query(Match).get(match_id)
    return jsonify({
        'match': match.to_dict(only=(
            'id', 'home_team', 'away_team', 'match_date',
            'home_score', 'away_score', 'is_played', 'tour_number'
        ))
    })


@blueprint.route('/api/matches', methods=['POST'])
def create_match():
    try:
        db_sess = db_session.create_session()
        match = Match(
            home_team=request.json['home_team'],
            away_team=request.json['away_team'],
            match_date=datetime.strptime(request.json['match_date'], '%Y-%m-%dT%H:%M'),
            tour_number=request.json['tour_number'],
            home_score=request.json.get('home_score'),
            away_score=request.json.get('away_score'),
            is_played=request.json.get('is_played', False)
        )
        db_sess.add(match)
        db_sess.commit()
        return jsonify({'id': match.id}), 201
    except Exception as e:
        return make_response(jsonify({'error': str(e)}), 400)


@blueprint.route('/api/matches/<int:match_id>', methods=['DELETE'])
def delete_match(match_id):
    db_sess = db_session.create_session()
    match = db_sess.query(Match).get(match_id)
    if not match:
        return make_response(jsonify({'error': 'Not found'}), 404)
    db_sess.delete(match)
    db_sess.commit()
    return jsonify({'success': 'OK'})


@blueprint.route('/api/table')
def get_table():
    db_sess = db_session.create_session()
    table = db_sess.query(RPLTable).order_by(RPLTable.position).all()
    return jsonify({
        'table': [team.to_dict(only=(
            'position', 'team', 'matches', 'wins',
            'draws', 'losses', 'goals_for', 'goals_against', 'points'
        )) for team in table]
    })