from sqlalchemy import and_
#from web import db, Progress
""" 
def track(korse, chapt, topic, user):
        #topiq, chapt, usr, points, score
        tracked = Progress.query.filter(and_(
            Progress.korse==korse, Progress.chapt==chapt, Progress.topiq==topic, Progress.usr==user) ).first()
        if not tracked:
            tracked.points += 1
            tracked.korse = korse
            tracked.chapt = chapt
            tracked.topiq = topic
            tracked.usr = user
            #self.progr.archievement += 1 
            db.session.add()
            db.session.commit() 
            """