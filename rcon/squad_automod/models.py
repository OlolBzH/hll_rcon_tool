
import logging
from dataclasses import field
from datetime import datetime
from enum import Enum, auto
from typing import Callable, List, Mapping

from pydantic.dataclasses import dataclass

logger = logging.getLogger(__name__)


class SquadHasLeader(Exception):
    pass


class SquadCycleOver(Exception):
    pass


@dataclass
class WatchStatus:
    warned: List[datetime] = field(default_factory=list)
    punished: Mapping[str, List[datetime]] = field(default_factory=dict)


class PunishStepState(Enum):
    wait = auto()
    immuned = auto()
    disabled = auto()
    apply = auto()
    go_to_next_step = auto()


@dataclass
class NoLeaderConfig:
    enabled: bool = True
    dry_run: bool = True
    discord_webhook_url: str = ''
    warn_message_header: str = "Attention : Chaque squad doit avoir un officier.\nVous allez être puni puis exclus."
    warn_message_footer: str = "La prochaine vérification aura lieu automatiquement dans 60s."
    # Set to 0 to disable, -1 for infinite warnings (will never go to punishes)
    number_of_warning: int = 3
    warning_interval_seconds: int = 60

    # Set to 0 to disable, -1 for infinite punish (will never go to kicks)
    number_of_punish: int = 3
    punish_interval_seconds: int = 60
    min_squad_players_for_punish: int = 3
    disable_punish_below_server_player_count: int = 60
    punish_message: str = (
        "Chaque squad doit avoir un officier.\nVous avez été puni par un robot.\n La prochaine vérification aura lieu automatiquement dans 60s."
    )

    kick_after_max_punish: bool = False
    disable_kick_below_server_player_count: int = 60
    min_squad_players_for_kick: int = 3
    kick_grace_period_seconds: int = 120
    kick_message: str = (
        "Chaque squad doit avoir un officier.\nVous avez échoué aux avertissements précédents et avez été puni en conséquence."
    )
    # roles: 'officer', 'antitank', 'automaticrifleman', 'assault', 'heavymachinegunner', 'support', 'sniper', 'spotter', 'rifleman', 'crewman', 'tankcommander', 'engineer', 'medic'
    immuned_roles: List[str] = field(default_factory=lambda: ["support", "sniper"])
    immuned_level_up_to: int = 1500


@dataclass
class APlayer:
    player: str
    squad: str
    team: str
    role: str = None
    lvl: int = None


@dataclass
class ASquad:
    name: str
    players: List[APlayer] = field(default_factory=list)

@dataclass
class PunitionsToApply:
    warning: Mapping[str, List[str]] = field(default_factory=lambda: {"allies": [], "axis": []})
    pending_warnings: Mapping[str, List[str]] = field(default_factory=lambda: {"allies": [], "axis": []})
    punish: List[APlayer] = field(default_factory=list)
    kick: List[APlayer] = field(default_factory=list)
    squads_state: List[dict] = field(default_factory=list)

    def add_squad_state(self, squad_name: str, squad: dict):
        try:
            self.squads_state.append(ASquad(
                name=squad_name,
                players=[
                    APlayer(player=p.get("name"), squad=p.get("unit_name"), team=p.get("team"), role=p.get("role"), lvl=p.get("level"))
                    for p in squad.get("players", [])
                ]
            ))
        except:
            logger.exception("Unable to add squad info")

    def __bool__(self):
        return any([self.warning.get("allies"), self.warning.get("axis"), self.kick, self.punish])

